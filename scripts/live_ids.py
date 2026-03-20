import os
import joblib
import pandas as pd
import numpy as np
import ipaddress
from scapy.all import sniff, IP, TCP
from datetime import datetime
from flow_state import FlowState

# =============================
# LOAD MODEL
# =============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

COLUMN_ORDER = list(scaler.feature_names_in_)

print("🔥 Live IDS Started...")
print("Model expects", len(COLUMN_ORDER), "features")

# =============================
# SETTINGS
# =============================

ATTACK_THRESHOLD = 0.90
FLOW_TIMEOUT = 2

flows = {}

# =============================
# UTILITIES
# =============================

def is_private(ip):
    return ipaddress.ip_address(ip).is_private


def ignore_noise(src_ip, dst_ip):

    # multicast
    if dst_ip.startswith("224.") or dst_ip.startswith("239."):
        return True

    # broadcast
    if dst_ip.endswith(".255"):
        return True

    # LAN to LAN traffic
    if is_private(src_ip) and is_private(dst_ip):
        return True

    return False


def get_key(pkt):

    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto

    sport = pkt[TCP].sport if TCP in pkt else 0
    dport = pkt[TCP].dport if TCP in pkt else 0

    return (ip.src, ip.dst, sport, dport, proto)


# =============================
# PACKET PROCESSOR
# =============================

def process_packet(pkt):

    key = get_key(pkt)
    if key is None:
        return

    src_ip, dst_ip, sport, dport, proto = key

    # Ignore LAN noise
    if ignore_noise(src_ip, dst_ip):
        return

    if key not in flows:
        flows[key] = FlowState(key, pkt)
    else:
        flows[key].update(pkt)

    if flows[key].flow_duration() > FLOW_TIMEOUT:

        features = flows[key].build_basic_features()

        aligned = {}

        for col in COLUMN_ORDER:
            aligned[col] = float(features.get(col, 0))

        df = pd.DataFrame([aligned])

        try:

            scaled = scaler.transform(df)

            prob = model.predict_proba(scaled)[0]
            attack_prob = prob[1]

            time_now = datetime.now().strftime("%H:%M:%S")

            proto_name = "TCP" if proto == 6 else "UDP"

            if attack_prob > ATTACK_THRESHOLD:

                print(
                    f"[{time_now}] 🚨 ATTACK ({attack_prob:.2f}) | {src_ip} → {dst_ip} | {proto_name} | Port {dport}"
                )

            else:

                print(
                    f"[{time_now}] ✔ BENIGN ({attack_prob:.2f}) | {src_ip} → {dst_ip} | {proto_name} | Port {dport}"
                )

        except Exception as e:
            print("Prediction Error:", e)

        del flows[key]


# =============================
# START IDS
# =============================

sniff(prn=process_packet, store=False)