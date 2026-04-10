import os
import socket
import sys
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
sys.stdout.reconfigure(line_buffering=True)   # disable output buffering for conda run
sys.stderr.reconfigure(line_buffering=True)
import time
import signal
import threading
import joblib
import pandas as pd
import numpy as np
import ipaddress
from queue import Queue, Empty
from scapy.all import sniff, IP, TCP, UDP, Ether, ARP, get_if_list, conf, srp, Dot11
from datetime import datetime
from flow_state import FlowState

# Known Scapy Windows bug — AttributeError in ObjectPipe __del__
# Harmless but spammy, suppress it silently
_original_unraisable = sys.unraisablehook
def _suppress_scapy_pipe_error(args):
    if args.exc_type is AttributeError and "ObjectPipe" in str(args.object.__class__):
        return
    _original_unraisable(args)
sys.unraisablehook = _suppress_scapy_pipe_error

# =============================
# LOAD MODEL
# =============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

COLUMN_ORDER = list(scaler.feature_names_in_)

# Silence joblib parallel verbose output
try:
    model.verbose = 0
    for est in getattr(model, "estimators_", []):
        est.verbose = 0
except Exception:
    pass


def predict_flow(features, meta):
    """Prediction — DataFrame passed to scaler to match training feature names."""
    aligned = {col: float(features.get(col, 0)) for col in COLUMN_ORDER}
    df = pd.DataFrame([aligned])
    scaled = scaler.transform(df)   # scaler fitted with feature names, df avoids warning
    prob = model.predict_proba(scaled)[0][1]
    return prob


print("=" * 65)
print("[NetGuardIDS] Live IDS Started -- Full Network Discovery Mode")
print(f"   Model expects {len(COLUMN_ORDER)} features")
print("=" * 65)

# =============================
# SETTINGS
# =============================

ATTACK_THRESHOLD = 0.40
FLOW_TIMEOUT = 2        # seconds -- flow will be considered complete after this
MIN_FLOW_PACKETS = 3    # minimum packets before predicting (avoids single-packet noise)

# Network Mode:
# True  --> monitor only this device's packets
# False --> capture all flows across the entire network
DEVICE_ONLY_MODE = False

# Set to a specific NPF GUID to force a particular interface, or leave as None to auto-detect.
# Auto-detect picks the first Ethernet interface that has an active IP address.
# This avoids crashes when you change Ethernet ports (Windows assigns a new GUID per port).
INTERFACE = None   # None = auto-detect active interface

# ARP Scan subnet -- used to discover nearby devices
# None = auto-detect from interface IP
ARP_SCAN_SUBNET = None  # e.g. "192.168.1.0/24"

flows = {}
flows_lock = threading.Lock()   # lock for thread-safe access to flows dict

mac_table = {}          # IP -> MAC address mapping
discovered_ips = {}     # IP -> {mac, first_seen, last_seen, packets}

# =============================
# ASYNC PREDICTION QUEUE
# =============================

prediction_queue = Queue(maxsize=500)   # queue for completed flows awaiting prediction


def prediction_worker():
    """
    Background thread: runs predictions independently from sniff().
    Packet capture will never be blocked.
    """
    while True:
        try:
            item = prediction_queue.get(timeout=1)
        except Empty:
            continue

        features, meta = item
        try:
            attack_prob = predict_flow(features, meta)

            src_ip, dst_ip, sport, dport, proto = meta["key"]
            time_now = datetime.now().strftime("%H:%M:%S")
            proto_name = format_proto(proto)

            src_type = "LAN" if is_private(src_ip) else "WAN"
            dst_type = "LAN" if is_private(dst_ip) else "WAN"
            direction = f"{src_type}->{dst_type}"

            src_mac  = mac_table.get(src_ip) or (gateway_mac if src_ip == gateway_ip else "??:??:??:??:??:??")
            dst_mac  = mac_table.get(dst_ip) or (gateway_mac if dst_ip == gateway_ip else "??:??:??:??:??:??")
            src_host = hostname_cache.get(src_ip, "")
            dst_host = hostname_cache.get(dst_ip, "")

            src_label = f"{src_ip} ({src_mac}{'  ' + src_host if src_host else ''})"
            dst_label = f"{dst_ip} ({dst_mac}{'  ' + dst_host if dst_host else ''})"

            port_info = format_port_info(proto, sport, dport)

            if attack_prob > ATTACK_THRESHOLD:
                print(
                    f"[{time_now}] !! ATTACK  ({attack_prob:.2f}) | "
                    f"{src_label} -> {dst_label} | "
                    f"{port_info} | {proto_name} | {direction}"
                )
            else:
                print(
                    f"[{time_now}]    BENIGN  ({attack_prob:.2f}) | "
                    f"{src_label} -> {dst_label} | "
                    f"{port_info} | {proto_name} | {direction}"
                )
        except Exception as e:
            print(f"[Prediction Error] {e}")

        prediction_queue.task_done()


# =============================
# UTILITIES
# =============================

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_multicast_or_broadcast(dst_ip):
    if dst_ip.startswith("224.") or dst_ip.startswith("239."):
        return True
    if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
        return True
    return False


def should_ignore(src_ip, dst_ip):
    if is_multicast_or_broadcast(dst_ip):
        return True
    if DEVICE_ONLY_MODE:
        if is_private(src_ip) and is_private(dst_ip):
            return True
    return False


def get_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        # ICMP and other protocols don't have ports
        # Store ICMP type/code in sport/dport for display purposes
        from scapy.all import ICMP
        if ICMP in pkt:
            sport = pkt[ICMP].type
            dport = pkt[ICMP].code
        else:
            sport = 0
            dport = 0
    return (ip.src, ip.dst, sport, dport, proto)


# Common IP protocol numbers
_PROTO_NAMES = {
    1:  "ICMP",
    2:  "IGMP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# ICMP type → human-readable name
_ICMP_TYPES = {
    0: "Echo Reply",
    3: "Dest Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advert",
    10: "Router Solicit",
    11: "Time Exceeded",
    12: "Param Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    30: "Traceroute",
}


def format_proto(proto):
    return _PROTO_NAMES.get(proto, f"PROTO-{proto}")


def format_port_info(proto, sport, dport):
    """Return a meaningful port/info string based on protocol."""
    if proto == 6 or proto == 17:   # TCP or UDP
        return f"Port {dport}"
    elif proto == 1:                 # ICMP
        icmp_name = _ICMP_TYPES.get(sport, f"Type-{sport}")
        return f"ICMP {icmp_name}"
    elif sport == 0 and dport == 0:
        return "No Port"
    else:
        return f"Port {dport}"


hostname_queue = Queue()   # IPs waiting for hostname resolution
hostname_cache = {}        # IP -> hostname (resolved asynchronously)


def hostname_worker():
    """Background thread: resolves hostnames without blocking capture.

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

            # ── Method 1: reverse DNS ──
            try:
                name = socket.gethostbyaddr(str(ip))[0]
            except Exception:
                pass

            # ── Method 2: NetBIOS (LAN-only, when DNS fails) ──
            if not name and is_private(ip):
                try:
                    import subprocess
                    result = subprocess.run(
                        ["nbtstat", "-A", ip],
                        capture_output=True, text=True,
                        timeout=6, encoding="utf-8", errors="replace"
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

            hostname_cache[ip] = name
        hostname_queue.task_done()


def register_device(ip, mac):
    """Track a newly discovered device."""
    now = datetime.now().strftime("%H:%M:%S")
    if ip not in discovered_ips:
        discovered_ips[ip] = {
            "mac": mac,
            "first_seen": now,
            "last_seen": now,
            "packets": 1
        }
        hostname_queue.put(ip)   # resolve hostname in background
        print(f"  [NEW DEVICE] {ip}  MAC: {mac}  (first seen {now})")
    else:
        discovered_ips[ip]["last_seen"] = now
        discovered_ips[ip]["packets"] += 1
        if mac and mac != "??:??:??:??:??:??":
            discovered_ips[ip]["mac"] = mac

    # Always keep mac_table in sync so live output can show MAC
    if mac and mac != "??:??:??:??:??:??":
        mac_table[ip] = mac


# =============================
# ARP SCANNER (Active Discovery)
# =============================

def get_local_subnet(iface):
    """Derive the local subnet from the given interface."""
    try:
        from scapy.all import get_if_addr
        local_ip = get_if_addr(iface)
        if not local_ip or local_ip == "0.0.0.0":
            return None
        # assume /24 subnet
        parts = local_ip.rsplit(".", 1)
        subnet = parts[0] + ".0/24"
        return subnet, local_ip
    except Exception as e:
        return None


def arp_scan(subnet, iface):
    """Send an ARP broadcast — only print newly discovered devices."""
    try:
        arp_req = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_req

        answered, unanswered = srp(packet, iface=iface, timeout=3, verbose=False)

        new_found = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            if ip not in discovered_ips:
                new_found.append((ip, mac))
            register_device(ip, mac)   # [NEW DEVICE] is printed inside only for new entries

        # Do not print anything if periodic rescan found nothing new
        if new_found:
            pass   # register_device already printed [NEW DEVICE]
        # else: nothing to print — no need to show the same devices again

        return answered

    except Exception as e:
        print(f"[ARP SCAN] Error: {e}")
        return []


def periodic_arp_scan(subnet, iface, interval=30):
    """Run ARP scan every few seconds to detect new devices."""
    while True:
        time.sleep(interval)
        arp_scan(subnet, iface)


# =============================
# ARP SPOOFING (MITM — Full Network Capture)
# =============================

# Whether ARP spoofing is enabled
ARP_SPOOF_ENABLED = True   # set to False if you only want to monitor your own traffic

gateway_ip = None    # Router/Gateway IP
gateway_mac = None   # Router/Gateway MAC
my_mac = None        # This machine's MAC address
spoof_active = True  # Controls whether the spoof loop keeps running


def get_mac(ip, iface):
    """Resolve the MAC address of a given IP via ARP."""
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = ether / arp
        answered, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
        if answered:
            return answered[0][1].hwsrc
    except Exception:
        pass
    return None


def get_own_mac(iface):
    """Get this machine's MAC address directly from the interface (no ARP needed)."""
    try:
        from scapy.all import get_if_hwaddr
        mac = get_if_hwaddr(iface)
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass
    return None


def get_gateway_ip(local_ip):
    """Detect the real gateway IP from the routing table (not hardcoded .1)."""
    # Method 1: use netifaces if available
    try:
        import netifaces
        gws = netifaces.gateways()
        default_gw = gws.get("default", {}).get(netifaces.AF_INET)
        if default_gw:
            return default_gw[0]
    except ImportError:
        pass
    except Exception:
        pass
    # Method 2: parse 'route print' output on Windows
    try:
        import subprocess
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]   # Gateway column
    except Exception:
        pass
    # Fallback: assume .1
    return local_ip.rsplit(".", 1)[0] + ".1"


def spoof_target(target_ip, target_mac, spoof_ip, iface):
    """
    Tell target_ip: 'MAC of spoof_ip = my MAC'
    e.g. Tell the device: 'MAC of the router = my MAC'
    """
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2,           # ARP reply
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=my_mac
        )
        conf.L2socket(iface=iface).send(pkt)
    except Exception:
        pass


def restore_arp(target_ip, target_mac, real_ip, real_mac, iface):
    """Restore the ARP table — send the real MAC back on exit."""
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=real_ip,
            hwsrc=real_mac
        )
        sock = conf.L2socket(iface=iface)
        for _ in range(5):   # send 5 times to ensure delivery
            sock.send(pkt)
            time.sleep(0.2)
    except Exception:
        pass


def enable_ip_forwarding():
    """Enable Windows IP forwarding so traffic is forwarded through this machine."""
    try:
        import subprocess
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface",
             "Ethernet", "forwarding=enabled"],
            capture_output=True
        )
        # Also try the registry method
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print("[*] IP Forwarding: ENABLED")
    except Exception as e:
        print(f"[!] IP Forwarding could not be enabled: {e}")
        print("    Run manually: netsh interface ipv4 set interface Ethernet forwarding=enabled")


def disable_ip_forwarding():
    """Disable IP forwarding on exit."""
    try:
        import subprocess
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface",
             "Ethernet", "forwarding=disabled"],
            capture_output=True
        )
    except Exception:
        pass


def arp_spoof_loop(iface):
    """
    Continuously spoof all devices:
    - Tell every LAN device: 'MAC of the gateway = my MAC'
    - Tell the gateway: 'MAC of every device = my MAC'
    → All traffic will pass through this machine
    """
    global spoof_active
    print(f"\n[ARP SPOOF] Started — Gateway: {gateway_ip} ({gateway_mac})")
    print(f"[ARP SPOOF] My MAC: {my_mac}")
    print(f"[ARP SPOOF] Spoofing all LAN devices...\n")

    while spoof_active:
        targets = list(discovered_ips.items())
        for ip, info in targets:
            mac = info.get("mac", "")
            if not mac or mac == "??:??:??:??:??:??":
                continue
            if ip == gateway_ip or not is_private(ip):   # fix: was hardcoded 192.168. only
                continue
            # Tell the device: MAC of the gateway = my MAC
            spoof_target(ip, mac, gateway_ip, iface)
            # Tell the gateway: MAC of this device = my MAC
            if gateway_mac:
                spoof_target(gateway_ip, gateway_mac, ip, iface)

        time.sleep(2)   # refresh spoof every 2 seconds


def stop_arp_spoof(iface):
    """Stop ARP spoofing and restore all ARP tables."""
    global spoof_active
    spoof_active = False
    print("\n[ARP SPOOF] Stopping — restoring real ARP tables...")
    targets = list(discovered_ips.items())
    for ip, info in targets:
        mac = info.get("mac", "")
        if not mac or ip == gateway_ip or not is_private(ip):   # fix: was hardcoded 192.168. only
            continue
        restore_arp(ip, mac, gateway_ip, gateway_mac, iface)
        if gateway_mac:
            restore_arp(gateway_ip, gateway_mac, ip, mac, iface)
    disable_ip_forwarding()
    print("[ARP SPOOF] Restored. ✓")


# =============================
# PACKET PROCESSOR (Fast — no blocking)
# =============================

def handle_arp(pkt):
    """Learn IP/MAC mappings from ARP packets."""
    if ARP in pkt:
        arp = pkt[ARP]
        # Learn IP from both ARP requests and replies
        if arp.psrc and arp.psrc != "0.0.0.0":
            register_device(arp.psrc, arp.hwsrc)
        if arp.pdst and arp.pdst != "0.0.0.0" and arp.op == 2:  # ARP reply
            register_device(arp.pdst, arp.hwdst)


def process_packet(pkt):
    """
    Only collect packet data and update the flow.
    No prediction here — enqueue for the background worker.
    """
    # Also learn IPs from ARP packets (passive learning)
    if ARP in pkt:
        handle_arp(pkt)
        return

    key = get_key(pkt)
    if key is None:
        return

    src_ip, dst_ip, sport, dport, proto = key

    if should_ignore(src_ip, dst_ip):
        return

    # Update MAC + IP mapping from sender only.
    # With ARP spoofing active, Ether.dst is always OUR MAC (devices send to us).
    # Using Ether.dst would corrupt the MAC table — all IPs would get our MAC.
    # Ether.src = real sending device MAC, so only learn from source.
    if Ether in pkt:
        mac_table[src_ip] = pkt[Ether].src
        register_device(src_ip, pkt[Ether].src)
        register_device(dst_ip, "")   # dst MAC unknown at L2 when spoofing
    else:
        register_device(src_ip, "")
        register_device(dst_ip, "")

    with flows_lock:
        if key not in flows:
            flows[key] = FlowState(key, pkt)
        else:
            flows[key].update(pkt)

        if flows[key].flow_duration() > FLOW_TIMEOUT:
            flow = flows[key]
            del flows[key]

            # Skip prediction if too few packets — not enough data for model
            if flow.total_packets < MIN_FLOW_PACKETS:
                return  # Discard sparse flow silently

            features = flow.build_basic_features()
            meta = {"key": key}
        else:
            return  # Flow not yet ready

    # Enqueue — prediction_worker will handle it in the background
    if not prediction_queue.full():
        prediction_queue.put((features, meta))


# =============================
# CLEANUP STALE FLOWS
# =============================

def cleanup_stale_flows():
    """Remove very old flows that never completed."""
    now = time.time()
    with flows_lock:
        stale = [k for k, v in flows.items() if (now - v.last_seen) > 30]
        for k in stale:
            del flows[k]
    if stale:
        print(f"[Cleanup] {len(stale)} stale flows removed.")


def print_device_summary():
    """Print a summary of all devices discovered so far."""
    print(f"\n{'='*90}")
    print(f"[SUMMARY] Total unique devices detected: {len(discovered_ips)}")
    print(f"  {'IP Address':<18} {'MAC Address':<20} {'Hostname':<30} {'First Seen':<10} Packets")
    print(f"  {'-'*18} {'-'*20} {'-'*30} {'-'*10} -------")
    for ip, info in sorted(discovered_ips.items(),
                           key=lambda x: x[1]["packets"], reverse=True):
        hostname = hostname_cache.get(ip, "resolving...")
        print(f"  {ip:<18} {info['mac']:<20} {hostname:<30} {info['first_seen']:<10} {info['packets']}")
    print(f"{'='*90}\n")


# =============================
# INTERFACE SELECTION
# =============================

def pick_interface():
    """Auto-detect the physical interface that carries the default route.

    Strategy (in order):
    1. netifaces → find which interface has the default gateway → convert to NPF GUID
    2. Fallback: first interface with a real routable IP (skip APIPA, loopback, 0.0.0.0)
    3. Last resort: Scapy default

    This reliably picks the real Ethernet/Wi-Fi adapter even when VMware,
    VirtualBox, or Hyper-V virtual adapters are present.
    """
    if INTERFACE:
        print(f"[*] Using manually set interface: {INTERFACE}")
        return INTERFACE

    from scapy.all import get_if_addr

    all_ifaces = get_if_list()

    # --- Method 1: netifaces default gateway interface ---
    # netifaces returns the GUID as '{XXXX-...}' on Windows.
    # NPF format is '\Device\NPF_{XXXX-...}' — construct directly, most reliable.
    try:
        import netifaces
        gws = netifaces.gateways()
        default_gw = gws.get("default", {}).get(netifaces.AF_INET)
        if default_gw:
            gw_ip = default_gw[0]
            gw_iface_name = default_gw[1]   # GUID e.g. "{0730DEE1-...}" — Windows returns 2 values
            # Direct construction of NPF path from GUID
            npf_iface = f"\\Device\\NPF_{gw_iface_name}"
            if npf_iface in all_ifaces:
                ip = get_if_addr(npf_iface)
                print(f"[*] Auto-selected via routing table : {npf_iface}  (IP: {ip}, GW: {gw_ip})")
                return npf_iface
            # Fallback substring match (in case format differs)
            for iface in all_ifaces:
                if gw_iface_name.lower() in str(iface).lower():
                    ip = get_if_addr(iface)
                    print(f"[*] Auto-selected via routing table : {iface}  (IP: {ip}, GW: {gw_ip})")
                    return iface
    except Exception:
        pass

    # --- Method 2: first real routable IP (skip APIPA / loopback / virtual) ---
    ethernet_candidates = []
    wifi_candidates = []
    for iface in all_ifaces:
        try:
            ip = get_if_addr(iface)
        except Exception:
            continue
        # Skip loopback, APIPA, unassigned, and common VMware/VirtualBox host-only subnets
        vmware_prefixes = ("192.168.40.", "192.168.80.", "192.168.56.", "192.168.99.", "10.0.2.", "172.16.0.")
        if (not ip or ip == "0.0.0.0"
                or ip.startswith("127.")
                or ip.startswith("169.254.")
                or any(ip.startswith(p) for p in vmware_prefixes)):
            continue
        iface_lower = str(iface).lower()
        if "wi-fi" in iface_lower or "wireless" in iface_lower or "wlan" in iface_lower:
            wifi_candidates.append((iface, ip))
        else:
            ethernet_candidates.append((iface, ip))

    if ethernet_candidates:
        chosen, ip = ethernet_candidates[0]
        print(f"[*] Auto-selected Ethernet interface: {chosen}  (IP: {ip})")
        return chosen

    if wifi_candidates:
        chosen, ip = wifi_candidates[0]
        print(f"[*] Auto-selected Wi-Fi interface   : {chosen}  (IP: {ip})")
        return chosen

    # --- Last resort ---
    print("[!] Could not find an active interface — falling back to Scapy default.")
    print("    Available interfaces:")
    for iface in all_ifaces:
        print(f"      {iface}")
    print("    Tip: Set INTERFACE manually at the top of live_ids.py if needed.")
    return str(conf.iface)


# =============================
# START IDS
# =============================

if __name__ == "__main__":

    iface = pick_interface()

    mode_label = "Device-Only" if DEVICE_ONLY_MODE else "Full Ethernet Network"
    print(f"[*] Mode        : {mode_label}")
    print(f"[*] Interface   : {iface}")
    print(f"[*] Threshold   : {ATTACK_THRESHOLD}")
    print(f"[*] Flow Timeout: {FLOW_TIMEOUT}s")
    print(f"[*] Promiscuous : ON")
    print("-" * 65)

    # --- Start background prediction worker ---
    worker_thread = threading.Thread(target=prediction_worker, daemon=True)
    worker_thread.start()
    print("[*] Background prediction worker started")

    # --- Start background hostname resolver ---
    hostname_thread = threading.Thread(target=hostname_worker, daemon=True)
    hostname_thread.start()
    print("[*] Background hostname resolver started\n")
    subnet_info = get_local_subnet(iface)
    if ARP_SCAN_SUBNET:
        subnet = ARP_SCAN_SUBNET
        local_ip = "N/A"
    elif subnet_info:
        subnet, local_ip = subnet_info
        print(f"[*] Local IP    : {local_ip}")
        print(f"[*] Scan Subnet : {subnet}")
    else:
        subnet = None
        print("[!] Could not detect local subnet for ARP scan.")

    print("-" * 65)

    # --- Initial ARP Scan (active discovery) ---
    if subnet:
        arp_scan(subnet, iface)

        # Periodic re-scan thread to detect new devices
        scan_thread = threading.Thread(
            target=periodic_arp_scan,
            args=(subnet, iface, 60),
            daemon=True
        )
        scan_thread.start()
        print("[*] Background ARP scanner started (every 60s)\n")

    # --- ARP Spoofing Setup ---
    if ARP_SPOOF_ENABLED and subnet_info:
        subnet, local_ip = subnet_info

        # Detect real gateway IP from routing table
        gateway_ip_detected = get_gateway_ip(local_ip)

        print(f"[*] Detecting gateway MAC for {gateway_ip_detected}...")
        gw_mac = get_mac(gateway_ip_detected, iface)
        my_mac_addr = get_own_mac(iface)   # use interface directly, not ARP on self
        print(f"[*] My MAC address     : {my_mac_addr}")

        if gw_mac and my_mac_addr:
            # Set global variables
            globals()["gateway_ip"] = gateway_ip_detected
            globals()["gateway_mac"] = gw_mac
            globals()["my_mac"] = my_mac_addr

            # Register gateway in mac_table so it shows up in logs
            mac_table[gateway_ip_detected] = gw_mac
            register_device(gateway_ip_detected, gw_mac)
            print(f"[*] Gateway           : {gateway_ip_detected}  MAC: {gw_mac}")

            enable_ip_forwarding()

            spoof_thread = threading.Thread(
                target=arp_spoof_loop,
                args=(iface,),
                daemon=True
            )
            spoof_thread.start()
        else:
            print(f"[!] Gateway MAC could not be detected — skipping ARP spoof")

    # --- Ctrl+C Signal Handler ---
    stop_flag = threading.Event()

    def handle_exit(sig, frame):
        print("\n[STOP] Ctrl+C — IDS is shutting down...")
        stop_flag.set()

    signal.signal(signal.SIGINT, handle_exit)

    print("[*] Starting live packet capture...\n")

    try:
        conf.use_npcap = True
        while not stop_flag.is_set():
            sniff(
                iface=iface,
                prn=process_packet,
                store=False,
                filter="",
                promisc=True,
                timeout=0.5
            )
    except PermissionError:
        print("[ERROR] Permission denied! Admin/root privileges se chalao:")
        print("   Windows: Run as Administrator")
        print("   Linux  : sudo python live_ids.py")
    finally:
        # Ctrl+C or any exit — cleanup is guaranteed
        if ARP_SPOOF_ENABLED and gateway_ip:
            stop_arp_spoof(iface)
        cleanup_stale_flows()
        print_device_summary()