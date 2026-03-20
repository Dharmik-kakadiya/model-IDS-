import os
import joblib
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# =============================
# LOAD MODEL + SCALER
# =============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

print("🚀 IDS Activated... Listening for packets")

# =============================
# FEATURE EXTRACTION (BASIC)
# =============================

def extract_features(packet):
    features = []

    if IP in packet:
        features.append(packet[IP].len)
        features.append(packet[IP].ttl)
    else:
        return None

    if TCP in packet:
        features.append(packet[TCP].sport)
        features.append(packet[TCP].dport)
    elif UDP in packet:
        features.append(packet[UDP].sport)
        features.append(packet[UDP].dport)
    else:
        features.extend([0, 0])

    return np.array(features).reshape(1, -1)

# =============================
# PACKET HANDLER
# =============================

def process_packet(packet):
    features = extract_features(packet)

    if features is not None:
        try:
            scaled = scaler.transform(features)
            prediction = model.predict(scaled)

            if prediction[0] == 1:
                print(f"[⚠ ATTACK DETECTED] {datetime.now()}")
            else:
                print(f"[✔ BENIGN] {datetime.now()}")

        except Exception as e:
            print("Feature mismatch:", e)

# =============================
# START SNIFFING
# =============================

sniff(prn=process_packet, store=False)