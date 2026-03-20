from scapy.all import sniff, IP, TCP
from flow_state import FlowState
import joblib
import os
import numpy as np

# ----------------------------
# Load Model & Scaler
# ----------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

model = joblib.load(os.path.join(BASE_DIR, "models", "network_model.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "models", "scaler.pkl"))

# ----------------------------
# Column Order (78 Features)
# ----------------------------

COLUMN_ORDER = [
'Dst Port','Protocol','Flow Duration','Tot Fwd Pkts','Tot Bwd Pkts',
'TotLen Fwd Pkts','TotLen Bwd Pkts','Fwd Pkt Len Max','Fwd Pkt Len Min',
'Fwd Pkt Len Mean','Fwd Pkt Len Std','Bwd Pkt Len Max','Bwd Pkt Len Min',
'Bwd Pkt Len Mean','Bwd Pkt Len Std','Flow Byts/s','Flow Pkts/s',
'Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min',
'Fwd IAT Tot','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min',
'Bwd IAT Tot','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min',
'Fwd Header Len','Bwd Header Len','Fwd Pkts/s','Bwd Pkts/s',
'Pkt Len Min','Pkt Len Max','Pkt Len Mean','Pkt Len Std','Pkt Len Var',
'FIN Flag Cnt','SYN Flag Cnt','RST Flag Cnt','PSH Flag Cnt',
'ACK Flag Cnt','URG Flag Cnt','CWE Flag Count','ECE Flag Cnt',
'Down/Up Ratio','Fwd Seg Size Avg','Bwd Seg Size Avg',
'Subflow Fwd Pkts','Subflow Fwd Byts','Subflow Bwd Pkts','Subflow Bwd Byts',
'Init Fwd Win Byts','Init Bwd Win Byts','Fwd Act Data Pkts',
'Fwd Seg Size Min','Active Mean','Active Std','Active Max','Active Min',
'Idle Mean','Idle Std','Idle Max','Idle Min'
]

flows = {}
FLOW_TIMEOUT = 2   # seconds


def get_key(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto

    sport = pkt[TCP].sport if TCP in pkt else 0
    dport = pkt[TCP].dport if TCP in pkt else 0

    return (ip.src, ip.dst, sport, dport, proto)


def process_packet(pkt):
    key = get_key(pkt)
    if key is None:
        return

    if key not in flows:
        flows[key] = FlowState(key, pkt)
    else:
        flows[key].update(pkt)

    # Flow timeout check
    if flows[key].flow_duration() > FLOW_TIMEOUT:

        features = flows[key].build_basic_features()

        print("\n=== Flow Completed ===")
        print(features)

        # ----------------------------
        # Prediction Section
        # ----------------------------

        # Fill missing features with 0
        for col in COLUMN_ORDER:
            if col not in features:
                features[col] = 0

        # Align feature order
        vector = [float(features[col]) for col in COLUMN_ORDER]

        # Scale
        vector = scaler.transform([vector])

        # Predict
        prediction = model.predict(vector)[0]

        print("Prediction:", prediction)

        del flows[key]


print("Phase 1 Flow Engine Running...")
sniff(prn=process_packet, store=False)