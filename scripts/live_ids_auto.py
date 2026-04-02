import os
os.environ["PYTHONWARNINGS"] = "ignore"          # suppress ALL warnings globally
import socket
import sys
import warnings
warnings.filterwarnings("ignore")                # catch-all: suppress everything
sys.stdout.reconfigure(line_buffering=True, encoding='utf-8', errors='replace')
sys.stderr.reconfigure(line_buffering=True, encoding='utf-8', errors='replace')
import time
import signal
import threading
import subprocess
import joblib
import pandas as pd
import numpy as np
import ipaddress
from queue import Queue, Empty
from scapy.all import (
    sniff, IP, TCP, UDP, Ether, ARP, ICMP,
    get_if_list, conf, srp, Dot11,
    get_if_addr, get_if_hwaddr
)
from datetime import datetime
from flow_state import FlowState

# ─────────────────────────────────────────────
# Suppress known harmless Scapy Windows bug
# ─────────────────────────────────────────────
_original_unraisable = sys.unraisablehook
def _suppress_scapy_pipe_error(args):
    if args.exc_type is AttributeError and "ObjectPipe" in str(args.object.__class__):
        return
    _original_unraisable(args)
sys.unraisablehook = _suppress_scapy_pipe_error

# =============================
# LOAD MODEL
# =============================

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH  = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

COLUMN_ORDER = list(scaler.feature_names_in_)

try:
    model.verbose = 0
    for est in getattr(model, "estimators_", []):
        est.verbose = 0
except Exception:
    pass

print("=" * 70)
print("[NetGuardIDS] AUTO MODE — All Interfaces Network Monitor")
print("   Captures ALL communication: WiFi + Ethernet simultaneously")
print(f"   Model expects {len(COLUMN_ORDER)} features")
print("=" * 70)

# =============================
# SETTINGS
# =============================

ATTACK_THRESHOLD = 0.40
FLOW_TIMEOUT     = 2        # seconds — flow complete after this idle time
MIN_FLOW_PACKETS = 3        # minimum packets before model predicts

# False = capture FULL network (all devices via ARP spoof)
# True  = capture only this machine's own traffic
DEVICE_ONLY_MODE = False

# Virtual adapter subnets to skip (VMware / VirtualBox / Hyper-V)
VMWARE_PREFIXES = (
    "192.168.40.", "192.168.80.", "192.168.56.",
    "192.168.99.", "10.0.2.", "172.16.0.",
)

# ARP Spoofing — forces ALL LAN traffic through this machine
ARP_SPOOF_ENABLED = True

# =============================
# SHARED STATE
# =============================

flows      = {}
flows_lock = threading.Lock()

mac_table      = {}   # IP -> MAC
discovered_ips = {}   # IP -> {mac, first_seen, last_seen, packets, iface_label}
disc_lock      = threading.Lock()

# Per-interface info: npf_iface -> {label, local_ip, subnet, gateway_ip, gateway_mac, my_mac}
iface_info   = {}
spoof_active = True

# Packet counters (updated under counters_lock)
packet_count   = 0
dbg_arp_count  = 0
dbg_ip_count   = 0
dbg_flow_count = 0
counters_lock  = threading.Lock()

stop_flag = threading.Event()

# =============================
# QUEUES
# =============================

prediction_queue = Queue(maxsize=1000)
hostname_queue   = Queue()
hostname_cache   = {}   # IP -> hostname string


# =============================
# UTILITIES
# =============================

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_multicast_or_broadcast(ip):
    if ip.startswith("224.") or ip.startswith("239."):
        return True
    if ip.endswith(".255") or ip == "255.255.255.255":
        return True
    return False


def should_ignore(src_ip, dst_ip):
    if is_multicast_or_broadcast(dst_ip):
        return True
    # In DEVICE_ONLY_MODE skip all LAN↔LAN flows
    if DEVICE_ONLY_MODE and is_private(src_ip) and is_private(dst_ip):
        return True
    return False


def get_key(pkt):
    """Return a 5-tuple flow key or None if packet has no IP layer."""
    if IP not in pkt:
        return None
    ip    = pkt[IP]
    proto = ip.proto
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif ICMP in pkt:
        sport = pkt[ICMP].type   # ICMP type stored as "sport" for display
        dport = pkt[ICMP].code
    else:
        sport = 0
        dport = 0
    return (ip.src, ip.dst, sport, dport, proto)


_PROTO_NAMES = {
    1: "ICMP",  2: "IGMP",   6: "TCP",    17: "UDP",
    41: "IPv6", 47: "GRE",   50: "ESP",   51: "AH",
    58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

_ICMP_TYPES = {
    0: "Echo Reply",      3: "Dest Unreachable", 4: "Source Quench",
    5: "Redirect",        8: "Echo Request",     9: "Router Advert",
    10: "Router Solicit", 11: "Time Exceeded",   12: "Param Problem",
    13: "Timestamp",      14: "Timestamp Reply", 30: "Traceroute",
}


def format_proto(proto):
    return _PROTO_NAMES.get(proto, f"PROTO-{proto}")


def format_port_info(proto, sport, dport):
    if proto in (6, 17):   # TCP / UDP
        return f"Port {dport}"
    elif proto == 1:        # ICMP
        return f"ICMP {_ICMP_TYPES.get(sport, f'Type-{sport}')}"
    elif sport == 0 and dport == 0:
        return "No Port"
    else:
        return f"Port {dport}"


def iface_tag_str(iface_lbl):
    """Return a fixed-width [WiFi] or [ ETH ] tag for output alignment."""
    lbl = iface_lbl.lower()
    if any(k in lbl for k in ("wi-fi", "wifi", "wireless", "wlan")):
        return "[WiFi]"
    elif iface_lbl:
        return "[ ETH]"
    return "[    ]"


# =============================
# HOSTNAME RESOLVER
# =============================

def hostname_worker():
    """Background thread — resolves hostnames without blocking capture.

    Resolution order:
      1. Reverse DNS  (gethostbyaddr) — works for most routable IPs
      2. NetBIOS      (nbtstat -A)    — works for Windows LAN machines
                                        that have no PTR record in DNS
    """
    while True:
        try:
            ip = hostname_queue.get(timeout=2)
        except Empty:
            continue
        if ip not in hostname_cache:
            name = ""

            # ── Method 1: reverse DNS (1-second timeout) ──
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(1)
                try:
                    name = socket.gethostbyaddr(str(ip))[0]
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except Exception:
                pass

            # ── Method 2: NetBIOS (LAN-only, when DNS fails) ──
            if not name and is_private(ip):
                try:
                    result = subprocess.run(
                        ["nbtstat", "-A", ip],
                        capture_output=True, text=True,
                        timeout=1, encoding="utf-8", errors="replace"
                    )
                    for line in result.stdout.splitlines():
                        stripped = line.strip()
                        # nbtstat output: "HOSTNAME       <00>  UNIQUE  Registered"
                        if "<00>" in stripped and "UNIQUE" in stripped:
                            parts = stripped.split()
                            if parts:
                                name = parts[0].strip()
                                break
                except Exception:
                    pass

            hostname_cache[ip] = name if name else "-"
        hostname_queue.task_done()


# =============================
# DEVICE REGISTRY
# =============================

def register_device(ip, mac, iface_label=""):
    """Thread-safe device tracking. Prints [NEW DEVICE] only once per IP."""
    now = datetime.now().strftime("%H:%M:%S")
    with disc_lock:
        if ip not in discovered_ips:
            discovered_ips[ip] = {
                "mac":        mac or "??:??:??:??:??:??",
                "first_seen": now,
                "last_seen":  now,
                "packets":    1,
                "iface":      iface_label,
            }
            hostname_queue.put(ip)
            tag = iface_tag_str(iface_label)
            print(f"  [NEW DEVICE] {ip:<17} MAC: {mac or '??:??:??:??:??:??'}  {tag}  ({now})")
        else:
            entry = discovered_ips[ip]
            entry["last_seen"] = now
            entry["packets"]  += 1
            if mac and mac != "??:??:??:??:??:??":
                entry["mac"] = mac
            if not entry.get("iface") and iface_label:
                entry["iface"] = iface_label

        if mac and mac != "??:??:??:??:??:??":
            mac_table[ip] = mac


# =============================
# PREDICTION WORKER
# =============================

def prediction_worker():
    """Background thread — runs ML predictions without blocking capture."""
    while True:
        try:
            item = prediction_queue.get(timeout=1)
        except Empty:
            continue

        features, meta = item
        try:
            aligned     = {col: float(features.get(col, 0)) for col in COLUMN_ORDER}
            df          = pd.DataFrame([aligned])
            scaled      = scaler.transform(df)
            attack_prob = model.predict_proba(scaled)[0][1]

            src_ip, dst_ip, sport, dport, proto = meta["key"]
            iface_lbl  = meta.get("iface", "")
            time_now   = datetime.now().strftime("%H:%M:%S")
            proto_name = format_proto(proto)

            src_type  = "LAN" if is_private(src_ip) else "WAN"
            dst_type  = "LAN" if is_private(dst_ip) else "WAN"
            direction = f"{src_type}->{dst_type}"

            # Resolve gateway MACs from iface_info for display
            gw_src_mac = next(
                (i["gateway_mac"] for i in iface_info.values() if i.get("gateway_ip") == src_ip), None
            )
            gw_dst_mac = next(
                (i["gateway_mac"] for i in iface_info.values() if i.get("gateway_ip") == dst_ip), None
            )

            src_mac  = mac_table.get(src_ip) or gw_src_mac or "??:??:??:??:??:??"
            dst_mac  = mac_table.get(dst_ip) or gw_dst_mac or "??:??:??:??:??:??"
            src_host = hostname_cache.get(src_ip, "")
            dst_host = hostname_cache.get(dst_ip, "")

            src_label = f"{src_ip} ({src_mac}{('  ' + src_host) if src_host else ''})"
            dst_label = f"{dst_ip} ({dst_mac}{('  ' + dst_host) if dst_host else ''})"
            port_info = format_port_info(proto, sport, dport)
            tag       = iface_tag_str(iface_lbl)

            if attack_prob > ATTACK_THRESHOLD:
                print(
                    f"[{time_now}] !! ATTACK  ({attack_prob:.2f}) {tag} | "
                    f"{src_label} -> {dst_label} | "
                    f"{port_info} | {proto_name} | {direction}"
                )
            else:
                print(
                    f"[{time_now}]    BENIGN  ({attack_prob:.2f}) {tag} | "
                    f"{src_label} -> {dst_label} | "
                    f"{port_info} | {proto_name} | {direction}"
                )
        except Exception as e:
            print(f"[Prediction Error] {e}")

        prediction_queue.task_done()


# =============================
# PACKET PROCESSOR
# =============================

def _get_own_macs():
    """Return a set of all our own MAC addresses across all active interfaces."""
    return {info["my_mac"].lower() for info in iface_info.values()
            if info.get("my_mac")}


def handle_arp(pkt, iface_lbl):
    """
    Learn IP->MAC mappings from ARP packets passively.

    IMPORTANT: When ARP spoofing is active, WE send ARP replies with
    hwsrc=our_mac and psrc=gateway_ip (or device_ip). Scapy sniffs these
    packets back from the wire. Without filtering, we would register:
        gateway_ip -> our_mac   (corrupts gateway MAC)
        device_ip  -> our_mac   (corrupts every device MAC)
    Fix: skip any ARP where hwsrc == one of our own MACs.
    """
    arp = pkt[ARP]
    own_macs = _get_own_macs()

    # Skip our own spoofed ARP replies
    if arp.hwsrc and arp.hwsrc.lower() in own_macs:
        return

    if arp.psrc and arp.psrc != "0.0.0.0":
        register_device(arp.psrc, arp.hwsrc, iface_lbl)
    if arp.pdst and arp.pdst != "0.0.0.0" and arp.op == 2:  # ARP reply only
        register_device(arp.pdst, arp.hwdst, iface_lbl)


def make_packet_handler(iface, iface_lbl):
    """
    Returns a packet-processing closure bound to a specific interface.
    Each sniff thread gets its own handler so iface_lbl is captured correctly.
    """
    def process_packet(pkt):
        global packet_count, dbg_arp_count, dbg_ip_count, dbg_flow_count

        with counters_lock:
            packet_count += 1

        # ── ARP: learn MAC mappings passively ──
        if ARP in pkt:
            with counters_lock:
                dbg_arp_count += 1
            handle_arp(pkt, iface_lbl)
            return

        # ── Dot11 (Wi-Fi monitor mode) — usually Ether headers are present anyway ──
        if Dot11 in pkt and Ether not in pkt and IP in pkt:
            src_ip = pkt[IP].src
            if pkt.addr2:
                register_device(src_ip, pkt.addr2, iface_lbl)

        key = get_key(pkt)
        if key is None:
            return  # no IP layer

        with counters_lock:
            dbg_ip_count += 1

        src_ip, dst_ip, sport, dport, proto = key

        if should_ignore(src_ip, dst_ip):
            return

        # Learn MAC from Ethernet source ONLY.
        # When ARP spoofing is on, dst MAC = our MAC (devices send to us
        # thinking we are the gateway) — do NOT learn from dst.
        #
        # IMPORTANT: When OS IP-forwarding is active, it creates new Ethernet
        # frames with Ether.src = our_mac for forwarded packets. Sniffing these
        # would associate our_mac with the original device's IP — corrupting
        # the MAC table. Fix: skip MAC learning when src_mac == our own MAC.
        own_macs = _get_own_macs()

        if Ether in pkt:
            src_mac = pkt[Ether].src
            if src_mac.lower() not in own_macs:   # skip our own forwarded frames
                register_device(src_ip, src_mac, iface_lbl)
            register_device(dst_ip, "", iface_lbl)
        elif Dot11 in pkt and pkt.addr2:
            src_mac = pkt.addr2
            if src_mac.lower() not in own_macs:
                register_device(src_ip, src_mac, iface_lbl)
            register_device(dst_ip, "", iface_lbl)
        else:
            register_device(src_ip, "", iface_lbl)
            register_device(dst_ip, "", iface_lbl)

        with counters_lock:
            dbg_flow_count += 1

        # ── Flow accumulation + timeout check ──
        with flows_lock:
            if key not in flows:
                flows[key] = FlowState(key, pkt)
            else:
                flows[key].update(pkt)

            if flows[key].flow_duration() > FLOW_TIMEOUT:
                flow = flows.pop(key)
            else:
                return  # flow not ready yet

        if flow.total_packets < MIN_FLOW_PACKETS:
            return  # discard sparse flows — too little data for the model

        features = flow.build_basic_features()
        meta     = {"key": key, "iface": iface_lbl}

        if not prediction_queue.full():
            prediction_queue.put((features, meta))

    return process_packet


# =============================
# STALE FLOW CLEANUP
# =============================

def cleanup_stale_flows():
    now = time.time()
    with flows_lock:
        stale = [k for k, v in flows.items() if (now - v.last_seen) > 30]
        for k in stale:
            del flows[k]
    if stale:
        print(f"[Cleanup] {len(stale)} stale flows removed.")


# =============================
# DEVICE SUMMARY
# =============================

def print_device_summary():
    # Column widths
    W_IP   = 18
    W_MAC  = 19
    W_VIA  = 5
    W_HOST = 30
    W_FS   = 9    # First Seen
    W_LS   = 9    # Last Seen
    BORDER = 2 + W_IP + 1 + W_MAC + 1 + W_VIA + 1 + W_HOST + 1 + W_FS + 1 + W_LS + 1 + 7

    # Filter out VMware / virtual adapter IPs from the display
    real_devices = {
        ip: info for ip, info in discovered_ips.items()
        if not any(ip.startswith(p) for p in VMWARE_PREFIXES)
    }

    print(f"\n{'='*BORDER}")
    print(f"[SUMMARY] Unique devices across ALL interfaces: {len(real_devices)}")
    print(
        f"  {'IP Address':<{W_IP}} {'MAC Address':<{W_MAC}} {'Via':<{W_VIA}} "
        f"{'Hostname':<{W_HOST}} {'First Seen':<{W_FS}} {'Last Seen':<{W_LS}} Packets"
    )
    print(
        f"  {'-'*W_IP} {'-'*W_MAC} {'-'*W_VIA} "
        f"{'-'*W_HOST} {'-'*W_FS} {'-'*W_LS} -------"
    )
    for ip, info in sorted(real_devices.items(),
                           key=lambda x: x[1]["packets"], reverse=True):
        raw_host  = hostname_cache.get(ip, None)
        if raw_host is None:
            hostname = "resolving..."
        elif raw_host == "-":
            hostname = "N/A"
        else:
            hostname = raw_host
        # Truncate long hostnames so they never break the column alignment
        if len(hostname) > W_HOST:
            hostname = hostname[:W_HOST - 2] + ".."
        itype     = iface_tag_str(info.get("iface", "")).strip("[]").strip()
        first     = info.get("first_seen", "")
        last      = info.get("last_seen",  "")
        print(
            f"  {ip:<{W_IP}} {info['mac']:<{W_MAC}} {itype:<{W_VIA}} "
            f"{hostname:<{W_HOST}} {first:<{W_FS}} {last:<{W_LS}} {info['packets']}"
        )
    print(f"{'='*BORDER}\n")


# =============================
# OWN MAC HELPER
# =============================

def get_own_mac_safe(iface):
    """Get this machine's MAC directly from the interface (no ARP needed)."""
    try:
        mac = get_if_hwaddr(iface)
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass
    return None


# =============================
# GATEWAY HELPERS
# =============================

def get_local_subnet(iface):
    """Return (subnet_cidr, local_ip) for the given interface, or None."""
    try:
        local_ip = get_if_addr(iface)
        if not local_ip or local_ip == "0.0.0.0":
            return None
        subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
        return subnet, local_ip
    except Exception:
        return None


def get_gateway_ip_for_iface(iface, local_ip):
    """
    Detect the gateway IP that corresponds to THIS specific interface.

    Strategy:
    1. netifaces — returns per-interface gateway (most accurate)
    2. 'route print' — parse default route, validate it's on this subnet
    3. Fallback — assume .1 on this interface's subnet
    """
    local_prefix = local_ip.rsplit(".", 1)[0]

    # Method 1: netifaces — iterate gateways and match interface
    try:
        import netifaces
        gws = netifaces.gateways()
        # gateways() returns {AF_INET: [(gw_ip, iface_name, is_default), ...]}
        for gw_ip, gw_iface, is_default in gws.get(netifaces.AF_INET, []):
            # Match by subnet prefix (same /24 block)
            if gw_ip.startswith(local_prefix + "."):
                return gw_ip
        # Fallback to default gateway if nothing matched
        default_gw = gws.get("default", {}).get(netifaces.AF_INET)
        if default_gw and default_gw[0].startswith(local_prefix + "."):
            return default_gw[0]
    except Exception:
        pass

    # Method 2: 'route print' — find a gateway on the same subnet
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw = parts[2]
                if gw.startswith(local_prefix + "."):
                    return gw
    except Exception:
        pass

    # Fallback: assume x.x.x.1
    return local_prefix + ".1"


def get_mac_for_ip(target_ip, iface, own_mac=None):
    """
    Resolve MAC of target_ip.
    Order: Windows ARP cache -> ping+cache -> L2 scapy ARP.
    Rejects our own MAC (proxy-ARP false positive guard).
    """
    own_norm = (own_mac or "").lower().strip()

    def _valid(m):
        return m and len(m) == 17 and m.lower() != own_norm

    def _read_arp_cache(ip):
        try:
            result = subprocess.run(
                ["arp", "-a", ip], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    m = parts[1].replace("-", ":").lower()
                    if _valid(m):
                        return m
        except Exception:
            pass
        return None

    # 1. ARP cache
    mac = _read_arp_cache(target_ip)
    if mac:
        return mac

    # 2. Ping then re-read cache
    try:
        subprocess.run(
            ["ping", "-n", "2", "-w", "1000", target_ip],
            capture_output=True, timeout=6
        )
        mac = _read_arp_cache(target_ip)
        if mac:
            return mac
    except Exception:
        pass

    # 3. L2 ARP via scapy
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        answered, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
        if answered:
            m = answered[0][1].hwsrc
            if _valid(m):
                return m
    except Exception:
        pass

    return None


# =============================
# ARP SCAN
# =============================

def arp_scan(subnet, iface, iface_lbl):
    """Send ARP broadcast on subnet and register all respondents."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, iface=iface, timeout=3, verbose=False)
        for _, received in answered:
            register_device(received.psrc, received.hwsrc, iface_lbl)
        return answered
    except Exception as e:
        print(f"[ARP SCAN] {iface_lbl}: {e}")
        return []


def periodic_arp_scan(subnet, iface, iface_lbl, interval=60):
    while not stop_flag.is_set():
        stop_flag.wait(interval)
        if not stop_flag.is_set():
            arp_scan(subnet, iface, iface_lbl)


# =============================
# ARP SPOOFING
# =============================

def spoof_target(target_ip, target_mac, spoof_ip, my_mac, iface):
    """Send a single ARP reply poisoning target_ip's cache."""
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=spoof_ip, hwsrc=my_mac
        )
        conf.L2socket(iface=iface).send(pkt)
    except Exception:
        pass


def restore_arp(target_ip, target_mac, real_ip, real_mac, iface):
    """Restore real ARP mappings on exit (sent 5× for reliability)."""
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=real_ip, hwsrc=real_mac
        )
        sock = conf.L2socket(iface=iface)
        for _ in range(5):
            sock.send(pkt)
            time.sleep(0.2)
    except Exception:
        pass


def arp_spoof_loop_for_iface(iface, info):
    """
    Continuously poison all devices on this interface's subnet:
      - Tell each device:  'MAC of gateway = my MAC'
      - Tell the gateway:  'MAC of each device = my MAC'
    Only targets IPs within this interface's own /24 subnet to avoid
    cross-interface collisions when both WiFi and Ethernet are active.
    """
    gw_ip         = info["gateway_ip"]
    gw_mac        = info["gateway_mac"]
    my_mac        = info["my_mac"]
    subnet_prefix = info["local_ip"].rsplit(".", 1)[0]  # e.g. "192.168.1"
    label         = info["label"]

    print(f"  [ARP SPOOF] {label} — Gateway: {gw_ip} ({gw_mac})  My MAC: {my_mac}")

    while spoof_active and not stop_flag.is_set():
        with disc_lock:
            targets = list(discovered_ips.items())

        for ip, dev in targets:
            mac = dev.get("mac", "")
            if not mac or mac == "??:??:??:??:??:??":
                continue
            if ip == gw_ip:
                continue
            if not is_private(ip):
                continue
            # ONLY spoof devices in THIS interface's subnet
            if not ip.startswith(subnet_prefix + "."):
                continue

            spoof_target(ip, mac, gw_ip, my_mac, iface)
            spoof_target(gw_ip, gw_mac, ip, my_mac, iface)

        stop_flag.wait(2)


def stop_all_arp_spoof():
    """Stop spoofing and restore all ARP tables across every interface."""
    global spoof_active
    spoof_active = False
    print("\n[ARP SPOOF] Stopping — restoring all ARP tables...")
    for iface, info in iface_info.items():
        gw_ip  = info.get("gateway_ip")
        gw_mac = info.get("gateway_mac")
        my_mac = info.get("my_mac")
        if not (gw_ip and gw_mac and my_mac):
            continue
        subnet_prefix = info["local_ip"].rsplit(".", 1)[0]
        with disc_lock:
            targets = list(discovered_ips.items())
        for ip, dev in targets:
            mac = dev.get("mac", "")
            if not mac or ip == gw_ip or not is_private(ip):
                continue
            if not ip.startswith(subnet_prefix + "."):
                continue
            restore_arp(ip, mac, gw_ip, gw_mac, iface)
            restore_arp(gw_ip, gw_mac, ip, mac, iface)
    print("[ARP SPOOF] All ARP tables restored. ✓")


# =============================
# IP FORWARDING
# =============================

def enable_ip_forwarding():
    """Enable Windows IP forwarding so captured packets are forwarded."""
    # Registry method
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print("[*] IP Forwarding: ENABLED (registry)")
    except Exception as e:
        print(f"[!] IP Forwarding registry failed: {e}")

    # netsh method — try for common interface names
    for name in ("Wi-Fi", "Ethernet", "Local Area Connection"):
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "interface",
                 name, "forwarding=enabled"],
                capture_output=True, timeout=3
            )
        except Exception:
            pass


def disable_ip_forwarding():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
    except Exception:
        pass
    for name in ("Wi-Fi", "Ethernet", "Local Area Connection"):
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "interface",
                 name, "forwarding=disabled"],
                capture_output=True, timeout=3
            )
        except Exception:
            pass


# =============================
# INTERFACE DISCOVERY
# =============================

def _get_wifi_guids_windows():
    """
    Use 'netsh wlan show interfaces' to get the GUIDs of all WiFi adapters.

    On Windows, netifaces.interfaces() returns raw GUIDs like:
        {0730DEE1-4A0B-4BD2-A90E-3CB3A54E8F52}
    These GUIDs do NOT contain strings like 'wi-fi' or 'wireless', so
    a simple string-search always fails and every interface gets labelled
    "Ethernet".

    netsh wlan show interfaces lists adapters like:
        GUID : 0730dee1-4a0b-4bd2-a90e-3cb3a54e8f52

    We extract these and compare against NPF GUID strings to identify
    which NPF adapter is a WiFi adapter.

    Returns: set of lowercase GUID strings (without braces)
    """
    wifi_guids = set()
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("guid"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    wifi_guids.add(parts[1].strip().lower())
    except Exception:
        pass
    return wifi_guids


def _get_friendly_names_windows():
    """
    Build a GUID -> friendly_name mapping using 'netsh interface show interface'.

    Output format (each adapter):
        Admin State    State          Type             Interface Name
        -------------------------------------------------------------------------
        Enabled        Connected      Dedicated        Ethernet
        Enabled        Connected      Dedicated        Wi-Fi

    We also run 'netsh interface ipv4 show addresses' to map friendly name -> IP,
    then combine with the IP->NPF GUID mapping from Scapy to produce:
        NPF_GUID -> friendly_name
    """
    # friendly_name -> IP
    name_to_ip = {}
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "addresses"],
            capture_output=True, text=True, timeout=5
        )
        current_name = None
        for line in result.stdout.splitlines():
            s = line.strip()
            if s.startswith('Configuration for interface'):
                # e.g. 'Configuration for interface "Wi-Fi"'
                current_name = s.split('"')[1] if '"' in s else None
            elif current_name and s.startswith("IP Address:"):
                ip = s.split(":", 1)[1].strip()
                name_to_ip[ip] = current_name
    except Exception:
        pass
    return name_to_ip   # ip -> friendly_name


def _npf_ip(npf):
    """Helper: get IP from NPF GUID, or empty string on failure."""
    try:
        ip = get_if_addr(npf)
        return ip if ip and ip != "0.0.0.0" else ""
    except Exception:
        return ""


def find_all_active_interfaces():
    """
    Find ALL active physical interfaces (WiFi + Ethernet).

    Windows-reliable detection strategy:
    1. Get WiFi adapter GUIDs via 'netsh wlan show interfaces'
    2. Get IP->friendly_name map via 'netsh interface ipv4 show addresses'
    3. For each NPF GUID from Scapy:
       - Get IP via get_if_addr()
       - Skip loopback / APIPA / unassigned / VMware subnets
       - Check if GUID is in wifi_guids set  -> label 'Wi-Fi'
       - Otherwise check friendly name for 'wi-fi'/'wireless' -> label 'Wi-Fi'
       - Else label 'Ethernet'

    Returns: list of (npf_guid, local_ip, label) tuples
    """
    all_npf   = get_if_list()      # Scapy NPF GUID list
    wifi_guids = _get_wifi_guids_windows()   # e.g. {'0730dee1-4a0b-...'}
    ip_to_name = _get_friendly_names_windows()  # e.g. {'192.168.1.5': 'Wi-Fi'}

    active   = []
    seen_ips = set()

    for npf in all_npf:
        # Get IP for this NPF adapter
        ip = _npf_ip(npf)
        if not ip or ip in seen_ips:
            continue
        if (ip.startswith("127.")
                or ip.startswith("169.254.")
                or ip == "0.0.0.0"
                or any(ip.startswith(p) for p in VMWARE_PREFIXES)):
            continue

        npf_lower = npf.lower()   # e.g. '\\device\\npf_{0730dee1-4a0b-...}'

        # Skip loopback
        if "loopback" in npf_lower:
            continue

        # ── Determine label ──
        # Method A: check if any WiFi GUID from netsh appears inside the NPF string
        is_wifi = any(guid in npf_lower for guid in wifi_guids)

        # Method B: check friendly name from netsh (fallback)
        if not is_wifi:
            friendly = ip_to_name.get(ip, "")
            is_wifi  = any(k in friendly.lower()
                           for k in ("wi-fi", "wifi", "wireless", "wlan"))

        label = "Wi-Fi" if is_wifi else "Ethernet"
        seen_ips.add(ip)
        active.append((npf, ip, label))

    return active


# =============================
# HEALTH MONITOR
# =============================

def health_monitor():
    last_total = last_arp = last_ip = last_flow = 0
    while not stop_flag.is_set():
        stop_flag.wait(10)
        if stop_flag.is_set():
            break
        d_total = packet_count  - last_total
        d_arp   = dbg_arp_count - last_arp
        d_ip    = dbg_ip_count  - last_ip
        d_flow  = dbg_flow_count - last_flow
        last_total, last_arp, last_ip, last_flow = (
            packet_count, dbg_arp_count, dbg_ip_count, dbg_flow_count
        )
        print(
            f"[Health +{d_total:>4}] "
            f"Total:{packet_count}  ARP:{d_arp}  IP:{d_ip}  FlowReached:{d_flow} | "
            f"ActiveFlows:{len(flows)}  Devices:{len(discovered_ips)}"
        )


# =============================
# SNIFF THREAD PER INTERFACE
# =============================

def sniff_on_iface(iface, iface_lbl):
    """Dedicated capture loop for one interface — runs in its own thread."""
    handler = make_packet_handler(iface, iface_lbl)
    conf.use_npcap = True
    while not stop_flag.is_set():
        try:
            sniff(
                iface=iface,
                prn=handler,
                store=False,
                filter="",      # capture everything: ARP + IP + all
                promisc=True,   # see all frames, not just ours
                timeout=0.5,
            )
        except Exception:
            pass   # transient error — keep looping


# =============================
# MAIN — START IDS
# =============================

if __name__ == "__main__":

    # ── Discover all connected interfaces ──
    active_ifaces = find_all_active_interfaces()

    if not active_ifaces:
        print("[ERROR] No active network interfaces found!")
        print("        Make sure you are connected to WiFi or Ethernet.")
        sys.exit(1)

    print(f"\n[*] Found {len(active_ifaces)} active interface(s):\n")
    for iface, ip, label in active_ifaces:
        print(f"    {iface_tag_str(label)}  {label:<10} IP: {ip:<16}  NPF: {iface}")
    print()

    print(f"[*] Mode        : {'Device-Only' if DEVICE_ONLY_MODE else 'FULL NETWORK — ALL devices'}")
    print(f"[*] ARP Spoof   : {'ON — forces all LAN traffic through this machine' if ARP_SPOOF_ENABLED else 'OFF'}")
    print(f"[*] Threshold   : {ATTACK_THRESHOLD}")
    print(f"[*] Flow Timeout: {FLOW_TIMEOUT}s  (min packets: {MIN_FLOW_PACKETS})")
    print(f"[*] Promiscuous : ON")
    print("-" * 70)

    # ── Background workers ──
    threading.Thread(target=prediction_worker, daemon=True).start()
    print("[*] Prediction worker started")

    for _hn_i in range(4):
        threading.Thread(target=hostname_worker, daemon=True, name=f"hostname-{_hn_i}").start()
    print("[*] Hostname resolver started (4 parallel workers)")

    threading.Thread(target=health_monitor, daemon=True).start()
    print("[*] Health monitor started (every 10s)")
    print()

    # ── Per-interface: ARP scan + ARP spoof setup ──
    for iface, local_ip, label in active_ifaces:
        subnet_info = get_local_subnet(iface)
        if not subnet_info:
            print(f"[!] {label}: Cannot detect subnet — skipping")
            continue

        subnet, _ = subnet_info
        print(f"[*] {label}: Scanning subnet {subnet} ...")
        arp_scan(subnet, iface, label)

        # Periodic background re-scan
        threading.Thread(
            target=periodic_arp_scan,
            args=(subnet, iface, label, 60),
            daemon=True
        ).start()

        # ARP spoof setup
        if ARP_SPOOF_ENABLED:
            gw_ip  = get_gateway_ip_for_iface(iface, local_ip)
            my_mac = get_own_mac_safe(iface)
            gw_mac = get_mac_for_ip(gw_ip, iface, own_mac=my_mac)

            print(f"[*] {label}: Gateway={gw_ip}  GW_MAC={gw_mac}  My_MAC={my_mac}")

            if gw_mac and my_mac:
                iface_info[iface] = {
                    "label":       label,
                    "local_ip":    local_ip,
                    "subnet":      subnet,
                    "gateway_ip":  gw_ip,
                    "gateway_mac": gw_mac,
                    "my_mac":      my_mac,
                }
                mac_table[gw_ip] = gw_mac
                register_device(gw_ip, gw_mac, label)

                threading.Thread(
                    target=arp_spoof_loop_for_iface,
                    args=(iface, iface_info[iface]),
                    daemon=True
                ).start()
            else:
                print(f"[!] {label}: Gateway MAC not found — ARP spoof skipped")

    if ARP_SPOOF_ENABLED and iface_info:
        enable_ip_forwarding()

    # ── Start sniff threads (one per interface) ──
    print("\n[*] Starting packet capture on ALL interfaces simultaneously...\n")
    for iface, local_ip, label in active_ifaces:
        t = threading.Thread(
            target=sniff_on_iface,
            args=(iface, label),
            daemon=True,
            name=f"sniff-{label}"
        )
        t.start()
        print(f"[*] Sniffing [{label}] — {iface}")

    print(f"\n{'='*70}")
    print(f"  NetGuardIDS monitoring ALL {len(active_ifaces)} interface(s)")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*70}\n")

    # ── Ctrl+C handler ──
    def handle_exit(sig, frame):
        print("\n[STOP] Ctrl+C received — IDS shutting down...")
        stop_flag.set()

    signal.signal(signal.SIGINT, handle_exit)

    # ── Block main thread until Ctrl+C ──
    try:
        while not stop_flag.is_set():
            stop_flag.wait(1)
    finally:
        if ARP_SPOOF_ENABLED and iface_info:
            stop_all_arp_spoof()
            disable_ip_forwarding()
        cleanup_stale_flows()
        # Print summary immediately — show resolved hostnames as-is
        # (no blocking wait; unresolved IPs will show 'resolving..' or '-')
        print_device_summary()
