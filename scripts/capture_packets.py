import os
import joblib
import numpy as np
import ipaddress
from scapy.all import sniff, IP, TCP, UDP, conf, get_if_list
from datetime import datetime
from collections import defaultdict

# =============================
# LOAD MODEL + SCALER
# =============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

FEATURE_COUNT = scaler.n_features_in_

print("=" * 55)
print("🚀 IDS Activated — Ethernet Network Capture Mode")
print(f"   Model features: {FEATURE_COUNT}")
print("=" * 55)

# =============================
# SETTINGS
# =============================

# True  → sirf is device ke packets (purana behavior)
# False → poore Ethernet network ke saare devices ke packets
DEVICE_ONLY_MODE = False

INTERFACE = None         # None = auto, ya "Ethernet" / "Wi-Fi"

ATTACK_THRESHOLD = 0.90
FLOW_TIMEOUT = 2

flows = defaultdict(list)   # key → list of packets

# =============================
# UTILITIES
# =============================

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def should_ignore(src_ip, dst_ip):
    # Hamesha multicast/broadcast ignore
    if dst_ip.startswith("224.") or dst_ip.startswith("239."):
        return True
    if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
        return True

    if DEVICE_ONLY_MODE:
        # LAN-to-LAN skip (sirf device mode)
        if is_private(src_ip) and is_private(dst_ip):
            return True

    return False


def get_key(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        sport, dport = 0, 0

    return (ip.src, ip.dst, sport, dport, proto)


# =============================
# FEATURE EXTRACTION (FLOW-BASED)
# =============================

def extract_features(pkts):
    """
    Ek flow ke packets se basic features nikalte hain.
    Model ke FEATURE_COUNT features banana zaroori hai.
    """
    lengths = [len(p) for p in pkts]
    duration = float(pkts[-1].time - pkts[0].time) if len(pkts) > 1 else 1e-6
    duration = max(duration, 1e-6)

    features = [
        pkts[0][IP].len if IP in pkts[0] else 0,      # IP length
        pkts[0][IP].ttl if IP in pkts[0] else 0,      # TTL
        pkts[0][TCP].sport if TCP in pkts[0] else (pkts[0][UDP].sport if UDP in pkts[0] else 0),
        pkts[0][TCP].dport if TCP in pkts[0] else (pkts[0][UDP].dport if UDP in pkts[0] else 0),
        len(pkts),                                     # Total packets
        sum(lengths),                                  # Total bytes
        np.mean(lengths),                             # Mean packet length
        np.max(lengths),                              # Max packet length
        np.min(lengths),                              # Min packet length
        float(sum(lengths)) / duration,               # Bytes per second
        float(len(pkts)) / duration,                  # Packets per second
    ]

    # Pad ya trim karo model ke expected feature count tak
    if len(features) < FEATURE_COUNT:
        features.extend([0.0] * (FEATURE_COUNT - len(features)))
    else:
        features = features[:FEATURE_COUNT]

    return np.array(features, dtype=float).reshape(1, -1)


# =============================
# PACKET HANDLER
# =============================

def process_packet(pkt):
    key = get_key(pkt)
    if key is None:
        return

    src_ip, dst_ip, sport, dport, proto = key

    if should_ignore(src_ip, dst_ip):
        return

    flows[key].append(pkt)
    pkts = flows[key]

    # Flow timeout check
    if len(pkts) >= 2:
        duration = float(pkts[-1].time - pkts[0].time)
        if duration >= FLOW_TIMEOUT:
            _analyze_flow(key, pkts, src_ip, dst_ip, dport, proto)
            del flows[key]


def _analyze_flow(key, pkts, src_ip, dst_ip, dport, proto):
    features = extract_features(pkts)

    try:
        scaled = scaler.transform(features)
        prob = model.predict_proba(scaled)[0]
        attack_prob = prob[1]

        time_now = datetime.now().strftime("%H:%M:%S")
        proto_name = {6: "TCP", 17: "UDP"}.get(proto, f"P{proto}")
        src_type = "LAN" if is_private(src_ip) else "WAN"
        dst_type = "LAN" if is_private(dst_ip) else "WAN"
        direction = f"{src_type}→{dst_type}"

        if attack_prob > ATTACK_THRESHOLD:
            print(
                f"[{time_now}] ⚠ ATTACK ({attack_prob:.2f}) | "
                f"{src_ip} → {dst_ip}:{dport} | {proto_name} | {direction}"
            )
        else:
            print(
                f"[{time_now}] ✔ BENIGN ({attack_prob:.2f}) | "
                f"{src_ip} → {dst_ip}:{dport} | {proto_name} | {direction}"
            )

    except Exception as e:
        print(f"[Feature mismatch] {e}")


# =============================
# START SNIFFING
# =============================

if __name__ == "__main__":
    iface = INTERFACE if INTERFACE else str(conf.iface)
    mode_label = "Device-Only" if DEVICE_ONLY_MODE else "Full Ethernet Network"

    # Available interfaces dikhao
    all_ifaces = get_if_list()
    print("\n📋 Available Interfaces:")
    for i, ifc in enumerate(all_ifaces):
        marker = " ← (auto-selected)" if str(ifc) == str(iface) else ""
        print(f"   [{i}] {ifc}{marker}")
    print()

    print(f"📡 Mode     : {mode_label}")
    print(f"🔌 Interface: {iface}")
    print("🔓 Promiscuous: ON (surrounding network packets bhi capture honge)")
    print("-" * 55)

    try:
        sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            filter="ip",
            promisc=True          # ← ZAROORI: surrounding network detect karne ke liye
        )
    except PermissionError:
        print("❌ Admin privileges chahiye!")
        print("   Windows: Run as Administrator")
        print("   Linux  : sudo python capture_packets.py")
    except KeyboardInterrupt:
        print("\n⛔ Capture stopped.")