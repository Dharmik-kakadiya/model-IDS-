from scapy.all import sniff, IP, TCP
from flow_state import FlowState
import joblib
import os
import pandas as pd
from datetime import datetime

# =============================
# LOAD MODEL + SCALER
# =============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

COLUMN_ORDER = list(scaler.feature_names_in_)

print("🔥 Live IDS Started...")
print("Model expects", len(COLUMN_ORDER), "features")

flows = {}
FLOW_TIMEOUT = 2   # seconds


# =============================
# FLOW KEY (Normalized)
# =============================

def get_key(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    else:
        sport = 0
        dport = 0

    # Normalize direction (important)
    if (ip.src, sport) <= (ip.dst, dport):
        return (ip.src, ip.dst, sport, dport, proto)
    else:
        return (ip.dst, ip.src, dport, sport, proto)


# =============================
# PACKET PROCESSOR
# =============================

def process_packet(pkt):

    key = get_key(pkt)
    if key is None:
        return

    if key not in flows:
        flows[key] = FlowState(key, pkt)
    else:
        flows[key].update(pkt)

    # Flow timeout
    if flows[key].flow_duration() > FLOW_TIMEOUT:

        features = flows[key].build_basic_features()

        # Align features safely
        aligned = {}
        for col in COLUMN_ORDER:
            aligned[col] = float(features.get(col, 0))

        try:
            df = pd.DataFrame([aligned])
            scaled = scaler.transform(df)

            prediction = model.predict(scaled)[0]
            probability = model.predict_proba(scaled)[0]

            attack_prob = probability[1]

            src_ip = key[0]
            dst_ip = key[1]
            dport = key[3]
            proto = "TCP" if key[4] == 6 else "UDP"

            now = datetime.now().strftime("%H:%M:%S")

            if attack_prob > 0.90:
                print(f"[{now}] 🚨 ATTACK ({attack_prob:.2f}) | {src_ip} → {dst_ip} | {proto} | Port {dport}")
            elif attack_prob > 0.60:
                print(f"[{now}] ⚠ SUSPICIOUS ({attack_prob:.2f}) | {src_ip} → {dst_ip} | {proto} | Port {dport}")
            else:
                print(f"[{now}] ✔ BENIGN ({attack_prob:.2f}) | {src_ip} → {dst_ip} | {proto} | Port {dport}")

        except Exception as e:
            print("Prediction Error:", e)

        del flows[key]


# =============================
# START SNIFFING
# =============================

# Show available interfaces
from scapy.arch.windows import get_windows_if_list
print("\n📡 Available Interfaces:")
for i, iface in enumerate(get_windows_if_list()):
    print(f"  [{i}] {iface['name']} — {iface.get('description', '')}")

# Set your interface name here (copy from above list)
INTERFACE = None  # e.g., "Ethernet" or "Wi-Fi" — None = auto

print(f"\n🔥 Sniffing on: {'Auto' if INTERFACE is None else INTERFACE} (Promiscuous Mode ON)\n")
sniff(prn=process_packet, store=False, promisc=True, iface=INTERFACE)