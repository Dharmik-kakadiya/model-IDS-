"""
mobile_scanner.py  —  NetGuardIDS Mobile / Hidden Device Detector
==================================================================
Yeh script un devices ko detect karta hai jo normal ARP scan mein
nahi aate, khaas kar mobile phones:

  Method 1 → Passive DHCP Sniff   (phone connect hote hi milta hai)
  Method 2 → Passive mDNS Sniff   (Apple/Android service announcements)
  Method 3 → Passive SSDP Sniff   (UPnP broadcasts — smart TVs, phones)
  Method 4 → Active Ping Sweep     (poore subnet ko ping karo)
  Method 5 → Passive ARP Watch    (koi bhi ARP bheje toh pakdo)

Usage:
    python scripts/mobile_scanner.py

Needs: npcap + admin privileges
"""

import os
import sys
import socket
import subprocess
import threading
import ipaddress
import time
from datetime import datetime
from queue import Queue, Empty

os.environ["PYTHONWARNINGS"] = "ignore"
import warnings
warnings.filterwarnings("ignore")
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

from scapy.all import (
    sniff, ARP, IP, UDP, Ether, get_if_list, get_if_addr,
    conf, srp, BOOTP, DHCP, DNS, DNSRR
)

# ──────────────────────────────────────────────────────────────
# VENDOR OUI DATABASE  (top mobile vendors)
# ──────────────────────────────────────────────────────────────
OUI_TABLE = {
    # Apple (iPhone / iPad / Mac)
    "00:03:93": "Apple", "00:0a:27": "Apple", "00:0a:95": "Apple",
    "00:14:51": "Apple", "00:1e:52": "Apple", "00:1f:5b": "Apple",
    "00:25:00": "Apple", "00:26:bb": "Apple", "00:50:e4": "Apple",
    "04:0c:ce": "Apple", "04:15:52": "Apple", "04:26:65": "Apple",
    "04:54:53": "Apple", "04:db:56": "Apple", "04:f7:e4": "Apple",
    "08:6d:41": "Apple", "08:74:02": "Apple", "08:f4:ab": "Apple",
    "0c:74:c2": "Apple", "10:40:f3": "Apple", "14:5a:05": "Apple",
    "18:81:0e": "Apple", "1c:36:bb": "Apple", "1c:ab:a7": "Apple",
    "20:78:f0": "Apple", "20:a2:e4": "Apple", "24:a2:e1": "Apple",
    "28:cf:e9": "Apple", "2c:61:f6": "Apple", "30:10:e4": "Apple",
    "34:08:bc": "Apple", "38:c9:86": "Apple", "3c:07:54": "Apple",
    "3c:15:c2": "Apple", "40:30:04": "Apple", "44:4c:0c": "Apple",
    "48:43:7c": "Apple", "4c:57:ca": "Apple", "50:ea:d6": "Apple",
    "54:26:96": "Apple", "54:ae:27": "Apple", "58:b0:35": "Apple",
    "5c:f7:e6": "Apple", "60:03:08": "Apple", "60:69:44": "Apple",
    "64:20:0c": "Apple", "68:64:4b": "Apple", "6c:40:08": "Apple",
    "70:48:0f": "Apple", "70:cd:60": "Apple", "74:1b:b2": "Apple",
    "74:e1:b6": "Apple", "78:31:c1": "Apple", "7c:11:be": "Apple",
    "7c:6d:62": "Apple", "80:be:05": "Apple", "84:38:35": "Apple",
    "84:fc:fe": "Apple", "88:66:a5": "Apple", "8c:7b:9d": "Apple",
    "90:27:e4": "Apple", "90:3c:92": "Apple", "94:e9:6a": "Apple",
    "98:01:a7": "Apple", "98:5a:eb": "Apple", "9c:f4:8e": "Apple",
    "a0:99:9b": "Apple", "a4:67:06": "Apple", "a4:c3:61": "Apple",
    "a8:96:8a": "Apple", "ac:0d:1b": "Apple", "b4:8b:19": "Apple",
    "b8:c7:5d": "Apple", "b8:ff:61": "Apple", "bc:52:b7": "Apple",
    "c0:63:94": "Apple", "c4:2c:03": "Apple", "c8:2a:14": "Apple",
    "cc:08:8d": "Apple", "cc:c7:60": "Apple", "d0:03:4b": "Apple",
    "d4:f4:6f": "Apple", "d8:30:62": "Apple", "dc:2b:2a": "Apple",
    "dc:9b:9c": "Apple", "e0:ac:cb": "Apple", "e4:25:e7": "Apple",
    "e8:8d:28": "Apple", "ec:35:86": "Apple", "f0:18:98": "Apple",
    "f0:99:bf": "Apple", "f4:f1:5a": "Apple", "f8:27:93": "Apple",
    "fc:25:3f": "Apple",
    # Samsung (Galaxy phones)
    "00:07:ab": "Samsung", "00:12:47": "Samsung", "00:15:99": "Samsung",
    "00:17:c9": "Samsung", "04:18:d6": "Samsung", "04:b1:67": "Samsung",
    "08:08:c2": "Samsung", "08:d4:2b": "Samsung", "0c:89:10": "Samsung",
    "14:49:e0": "Samsung", "18:22:7e": "Samsung", "1c:66:aa": "Samsung",
    "20:13:e0": "Samsung", "24:4b:81": "Samsung", "28:27:bf": "Samsung",
    "2c:ae:2b": "Samsung", "30:19:66": "Samsung", "34:4d:f7": "Samsung",
    "38:1f:8d": "Samsung", "3c:62:00": "Samsung", "40:4e:36": "Samsung",
    "44:a7:cf": "Samsung", "48:44:f7": "Samsung", "4c:3c:16": "Samsung",
    "50:01:bb": "Samsung", "54:40:ad": "Samsung", "58:ef:68": "Samsung",
    "5c:2e:59": "Samsung", "60:a1:0a": "Samsung", "64:77:91": "Samsung",
    "68:eb:ae": "Samsung", "6c:83:36": "Samsung", "70:f9:27": "Samsung",
    "78:25:ad": "Samsung", "7c:0b:c6": "Samsung", "84:a4:66": "Samsung",
    "88:36:6c": "Samsung", "90:18:7c": "Samsung", "94:51:03": "Samsung",
    "98:52:3d": "Samsung", "9c:65:b0": "Samsung", "a0:0b:ba": "Samsung",
    "a4:eb:d3": "Samsung", "ac:5f:3e": "Samsung", "b0:47:bf": "Samsung",
    "b4:3a:28": "Samsung", "b8:5e:7b": "Samsung", "bc:20:a4": "Samsung",
    "c0:89:ab": "Samsung", "c4:42:02": "Samsung", "cc:07:ab": "Samsung",
    "d0:22:be": "Samsung", "d4:88:90": "Samsung", "d8:57:ef": "Samsung",
    "dc:71:96": "Samsung",
    # Xiaomi (Redmi, POCO, Mi)
    "00:9e:c8": "Xiaomi", "04:cf:8c": "Xiaomi", "0c:1d:af": "Xiaomi",
    "10:2a:b3": "Xiaomi", "18:59:36": "Xiaomi", "20:82:c0": "Xiaomi",
    "28:6c:07": "Xiaomi", "34:80:b3": "Xiaomi", "38:a4:ed": "Xiaomi",
    "40:31:3c": "Xiaomi", "4c:63:71": "Xiaomi", "50:64:2b": "Xiaomi",
    "58:44:98": "Xiaomi", "60:ab:14": "Xiaomi", "64:09:80": "Xiaomi",
    "68:df:dd": "Xiaomi", "74:51:ba": "Xiaomi", "78:02:f8": "Xiaomi",
    "7c:1d:d9": "Xiaomi", "80:35:c1": "Xiaomi", "88:c9:d0": "Xiaomi",
    "8c:be:be": "Xiaomi", "94:fb:a7": "Xiaomi", "9c:99:a0": "Xiaomi",
    "a0:86:c6": "Xiaomi", "a4:50:46": "Xiaomi", "ac:c1:ee": "Xiaomi",
    "b0:e2:35": "Xiaomi", "b4:0e:de": "Xiaomi", "b8:a9:d4": "Xiaomi",
    "c0:ee:fb": "Xiaomi", "c4:0b:cb": "Xiaomi", "d4:97:0b": "Xiaomi",
    "e4:46:da": "Xiaomi", "e8:ab:fa": "Xiaomi", "f0:b4:29": "Xiaomi",
    "f4:8b:32": "Xiaomi", "f8:a4:5f": "Xiaomi", "fc:64:ba": "Xiaomi",
    # OnePlus
    "04:d3:b5": "OnePlus", "08:f3:fb": "OnePlus", "20:0f:23": "OnePlus",
    "3c:28:6d": "OnePlus", "4c:8b:30": "OnePlus", "5c:e8:eb": "OnePlus",
    "64:cc:2e": "OnePlus", "78:9f:70": "OnePlus", "8c:8d:28": "OnePlus",
    "a8:9c:ed": "OnePlus", "ac:5f:3e": "OnePlus", "e0:d4:e8": "OnePlus",
    # Realme / OPPO / Vivo (common in India)
    "00:1e:a9": "OPPO",    "08:26:ae": "OPPO",    "1c:77:f6": "OPPO",
    "28:ba:b5": "OPPO",    "34:fc:ef": "OPPO",    "44:74:6c": "OPPO",
    "4c:1a:3d": "Realme",  "54:f6:02": "Realme",  "68:3e:26": "Realme",
    "00:17:be": "Vivo",    "04:03:d6": "Vivo",    "5c:0a:5b": "Vivo",
    "cc:2d:e0": "Vivo",    "e8:49:27": "Vivo",
    # Google Pixel
    "00:1a:11": "Google",  "30:fd:38": "Google",  "3c:5a:b4": "Google",
    "54:60:09": "Google",  "64:bc:0c": "Google",  "94:eb:2c": "Google",
    "a4:77:33": "Google",
}

MOBILE_VENDORS = {
    "Apple", "Samsung", "Xiaomi", "OnePlus", "OPPO",
    "Realme", "Vivo", "Google", "Huawei", "Motorola", "Nokia"
}

# ──────────────────────────────────────────────────────────────
# SHARED STATE
# ──────────────────────────────────────────────────────────────
found_lock = threading.Lock()
found_devices = {}   # ip -> {mac, vendor, methods, first_seen, hostname}

hostname_cache = {}
hostname_queue = Queue()

stop_flag = threading.Event()


def ts():
    return datetime.now().strftime("%H:%M:%S")


def lookup_vendor(mac: str) -> str:
    """OUI se vendor naam pata karo."""
    prefix = mac[:8].lower()
    return OUI_TABLE.get(prefix, "Unknown")


def is_mobile(vendor: str) -> bool:
    return vendor in MOBILE_VENDORS


def register(ip: str, mac: str, method: str, hostname: str = ""):
    """Thread-safe device registration."""
    vendor = lookup_vendor(mac) if mac and mac != "??:??:??:??:??:??" else "Unknown"
    now = ts()
    with found_lock:
        if ip not in found_devices:
            found_devices[ip] = {
                "mac": mac or "??:??:??:??:??:??",
                "vendor": vendor,
                "methods": {method},
                "first_seen": now,
                "hostname": hostname,
            }
            tag = "📱 MOBILE" if is_mobile(vendor) else "💻 DEVICE"
            print(
                f"  [{ts()}] {tag}  {ip:<17}  MAC: {mac or '??:??:??:??:??:??':<19}"
                f"  {vendor:<12}  [{method}]"
            )
            if not hostname:
                hostname_queue.put(ip)
        else:
            dev = found_devices[ip]
            dev["methods"].add(method)
            if mac and mac != "??:??:??:??:??:??":
                dev["mac"] = mac
                dev["vendor"] = vendor
            if hostname:
                dev["hostname"] = hostname


# ──────────────────────────────────────────────────────────────
# HOSTNAME RESOLVER
# ──────────────────────────────────────────────────────────────
def hostname_worker():
    while True:
        try:
            ip = hostname_queue.get(timeout=2)
        except Empty:
            continue
        if ip not in hostname_cache:
            name = "-"
            try:
                socket.setdefaulttimeout(1)
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            hostname_cache[ip] = name
            with found_lock:
                if ip in found_devices:
                    found_devices[ip]["hostname"] = name
        hostname_queue.task_done()


# ──────────────────────────────────────────────────────────────
# METHOD 1 — PASSIVE ARP WATCHER
# ──────────────────────────────────────────────────────────────
def passive_arp_handler(pkt):
    if ARP in pkt:
        arp = pkt[ARP]
        if arp.psrc and arp.psrc != "0.0.0.0":
            register(arp.psrc, arp.hwsrc, "ARP")


# ──────────────────────────────────────────────────────────────
# METHOD 2 — PASSIVE DHCP SNIFFER
# Phones send DHCP Discover/Request when joining network.
# DHCP Request contains hostname (option 12)!
# ──────────────────────────────────────────────────────────────
def dhcp_handler(pkt):
    if DHCP not in pkt:
        return
    opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
    # Message type: 1=Discover, 3=Request
    msg_type = opts.get("message-type", 0)
    if msg_type not in (1, 3):
        return

    mac = pkt[Ether].src if Ether in pkt else "??:??:??:??:??:??"

    # Option 50 = requested IP (in Request), Option 12 = hostname
    req_ip  = opts.get("requested_addr", "")
    name    = opts.get("hostname", b"")
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")

    ip = str(req_ip) if req_ip else "0.0.0.0 (Discovering)"
    register(ip, mac, "DHCP", hostname=name)


# ──────────────────────────────────────────────────────────────
# METHOD 3 — PASSIVE mDNS SNIFFER
# Apple, Android devices broadcast mDNS on 224.0.0.251:5353
# This reveals device names like "Dharmik's iPhone.local"
# ──────────────────────────────────────────────────────────────
def mdns_handler(pkt):
    if IP not in pkt or UDP not in pkt:
        return
    if pkt[UDP].dport != 5353 and pkt[UDP].sport != 5353:
        return
    src_ip  = pkt[IP].src
    src_mac = pkt[Ether].src if Ether in pkt else ""
    hostname = ""
    if DNS in pkt:
        dns = pkt[DNS]
        # Check answer records for PTR/A/AAAA
        for i in range(dns.ancount):
            try:
                rr = dns.an[i]
                if hasattr(rr, "rrname"):
                    name = rr.rrname
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    if name.endswith(".local."):
                        hostname = name.rstrip(".")
                        break
            except Exception:
                pass
        # Also check questions for device name hints
        if not hostname:
            for i in range(dns.qdcount):
                try:
                    qname = dns.qd[i].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    if ".local." in qname:
                        hostname = qname.strip(".").replace(".local", "")
                        break
                except Exception:
                    pass
    register(src_ip, src_mac, "mDNS", hostname=hostname)


# ──────────────────────────────────────────────────────────────
# METHOD 4 — PASSIVE SSDP SNIFFER
# Smart TVs, Chromecast, Android phones broadcast SSDP on 239.255.255.250:1900
# ──────────────────────────────────────────────────────────────
def ssdp_handler(pkt):
    if IP not in pkt or UDP not in pkt:
        return
    if pkt[UDP].dport != 1900 and pkt[UDP].sport != 1900:
        return
    src_ip  = pkt[IP].src
    src_mac = pkt[Ether].src if Ether in pkt else ""
    register(src_ip, src_mac, "SSDP")


# ──────────────────────────────────────────────────────────────
# COMBINED PASSIVE SNIFFER
# ──────────────────────────────────────────────────────────────
def passive_sniffer(iface):
    def handler(pkt):
        passive_arp_handler(pkt)
        dhcp_handler(pkt)
        mdns_handler(pkt)
        ssdp_handler(pkt)

    conf.use_npcap = True
    print(f"[*] Passive sniff started on {iface}")
    while not stop_flag.is_set():
        try:
            sniff(
                iface=iface,
                prn=handler,
                store=False,
                filter="arp or (udp and (port 67 or port 68 or port 5353 or port 1900))",
                promisc=True,
                timeout=1,
            )
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────
# METHOD 5 — ACTIVE PING SWEEP
# Windows ping every IP in subnet — touches sleeping devices
# ──────────────────────────────────────────────────────────────
def ping_sweep(subnet_cidr: str):
    net = ipaddress.IPv4Network(subnet_cidr, strict=False)
    hosts = list(net.hosts())
    print(f"[*] Ping sweep: {subnet_cidr}  ({len(hosts)} hosts)")

    def _ping(ip):
        try:
            r = subprocess.run(
                ["ping", "-n", "1", "-w", "500", str(ip)],
                capture_output=True, timeout=2
            )
            if r.returncode == 0:
                # IP responded — now get MAC from ARP cache
                try:
                    out = subprocess.run(
                        ["arp", "-a", str(ip)],
                        capture_output=True, text=True, timeout=2
                    ).stdout
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == str(ip):
                            mac = parts[1].replace("-", ":").lower()
                            register(str(ip), mac, "PING")
                            return
                except Exception:
                    pass
                register(str(ip), "", "PING")
        except Exception:
            pass

    # Parallel ping — 64 threads
    sem = threading.Semaphore(64)

    def worker(ip):
        with sem:
            _ping(ip)

    threads = []
    for ip in hosts:
        t = threading.Thread(target=worker, args=(ip,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(f"[*] Ping sweep complete — found {len(found_devices)} total devices so far")


# ──────────────────────────────────────────────────────────────
# ARP SCAN (active, faster than ping for LAN)
# ──────────────────────────────────────────────────────────────
def arp_scan(subnet: str, iface: str):
    print(f"[*] ARP scan: {subnet}")
    try:
        pkt          = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _  = srp(pkt, iface=iface, timeout=3, verbose=False)
        for _, rcv in answered:
            register(rcv.psrc, rcv.hwsrc, "ARP-Scan")
        print(f"[*] ARP scan got {len(answered)} replies")
    except Exception as e:
        print(f"[!] ARP scan error: {e}")


# ──────────────────────────────────────────────────────────────
# SUMMARY PRINTER
# ──────────────────────────────────────────────────────────────
def print_summary():
    print("\n" + "=" * 90)
    print(f"  SCAN COMPLETE — {len(found_devices)} Unique Devices Found")
    print("=" * 90)

    mobile_devs = {ip: d for ip, d in found_devices.items() if is_mobile(d["vendor"])}
    other_devs  = {ip: d for ip, d in found_devices.items() if not is_mobile(d["vendor"])}

    def print_group(label, devs):
        if not devs:
            return
        print(f"\n  ── {label} ({len(devs)}) ──")
        print(f"  {'IP':<17} {'MAC':<19} {'Vendor':<14} {'Hostname':<35} {'Methods'}")
        print(f"  {'-'*17} {'-'*19} {'-'*14} {'-'*35} {'-'*20}")
        for ip, d in sorted(devs.items()):
            methods  = "+".join(sorted(d["methods"]))
            hostname = d.get("hostname", "") or "-"
            if len(hostname) > 34:
                hostname = hostname[:32] + ".."
            print(
                f"  {ip:<17} {d['mac']:<19} {d['vendor']:<14} {hostname:<35} {methods}"
            )

    print_group("📱 MOBILE PHONES / TABLETS", mobile_devs)
    print_group("💻 OTHER DEVICES", other_devs)
    print("\n" + "=" * 90)

    if mobile_devs:
        print(f"\n  ✅ {len(mobile_devs)} mobile device(s) detected!")
    else:
        print("\n  ⚠️  No mobile phones detected.")
        print("     → Make sure phone is connected to Wi-Fi and screen is ON")
        print("     → Or try opening a browser on the phone while this scan runs")


# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────
def get_active_iface():
    """Find first non-loopback interface with a real IP."""
    for npf in get_if_list():
        try:
            ip = get_if_addr(npf)
            if ip and ip != "0.0.0.0" and not ip.startswith("127.") and not ip.startswith("169.254."):
                return npf, ip
        except Exception:
            pass
    return None, None


if __name__ == "__main__":
    print("=" * 70)
    print("  NetGuardIDS — Mobile & Hidden Device Scanner")
    print("  Detects phones via: ARP + DHCP + mDNS + SSDP + Ping Sweep")
    print("=" * 70)

    iface, local_ip = get_active_iface()
    if not iface:
        print("[ERROR] No active network interface found!")
        sys.exit(1)

    subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
    print(f"\n[*] Interface : {iface}")
    print(f"[*] Local IP  : {local_ip}")
    print(f"[*] Subnet    : {subnet}")
    print(f"[*] Listening for 60 seconds + active scanning...\n")

    # Start hostname workers
    for _ in range(4):
        threading.Thread(target=hostname_worker, daemon=True).start()

    # Start passive sniffer (background)
    threading.Thread(target=passive_sniffer, args=(iface,), daemon=True).start()

    # Active ARP scan
    arp_scan(subnet, iface)

    # Active Ping sweep (catches sleep-mode phones after ping wakes them)
    threading.Thread(target=ping_sweep, args=(subnet,), daemon=True).start()

    print(f"\n[*] Passive listening ON — any device that sends a packet will be caught")
    print(f"[*] Tip: Open your phone's browser or send a WhatsApp message to trigger detection\n")

    # Listen passively for 60 seconds
    try:
        for i in range(6):
            time.sleep(10)
            with found_lock:
                total = len(found_devices)
                mobile = sum(1 for d in found_devices.values() if is_mobile(d["vendor"]))
            print(f"  [{ts()}] Progress: {total} devices found ({mobile} mobile/phone)")
    except KeyboardInterrupt:
        print("\n[STOP] Scan interrupted by user")

    stop_flag.set()
    time.sleep(1)   # let threads finish

    print_summary()
