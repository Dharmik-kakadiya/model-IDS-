import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

PCAP_PATH = "../scripts/benign_traffic.pcap"
OUTPUT_PATH = "../data/benign_live1.csv"

print("📂 Reading PCAP...")
packets = rdpcap(PCAP_PATH)

flows = defaultdict(list)

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
        sport = 0
        dport = 0

    return (ip.src, ip.dst, sport, dport, proto)

print("🔄 Building flows...")

for pkt in packets:
    key = get_key(pkt)
    if key:
        flows[key].append(pkt)

rows = []

print("📊 Extracting features...")

for key, pkts in flows.items():

    lengths = [len(p) for p in pkts]
    duration = pkts[-1].time - pkts[0].time if len(pkts) > 1 else 0

    row = {
        # Core features
        "Dst Port": key[3],
        "Protocol": key[4],
        "Flow Duration": duration,
        "Tot Fwd Pkts": len(pkts),
        "Tot Bwd Pkts": 0,

        "TotLen Fwd Pkts": sum(lengths),
        "TotLen Bwd Pkts": 0,

        "Fwd Pkt Len Max": np.max(lengths),
        "Fwd Pkt Len Min": np.min(lengths),
        "Fwd Pkt Len Mean": np.mean(lengths),
        "Fwd Pkt Len Std": np.std(lengths),

        "Bwd Pkt Len Max": 0,
        "Bwd Pkt Len Min": 0,
        "Bwd Pkt Len Mean": 0,
        "Bwd Pkt Len Std": 0,

        "Flow Byts/s": 0,
        "Flow Pkts/s": 0,

        "Flow IAT Mean": 0,
        "Flow IAT Std": 0,
        "Flow IAT Max": 0,
        "Flow IAT Min": 0,

        "Fwd IAT Tot": 0,
        "Fwd IAT Mean": 0,
        "Fwd IAT Std": 0,
        "Fwd IAT Max": 0,
        "Fwd IAT Min": 0,

        "Bwd IAT Tot": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,

        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,

        "Fwd Header Len": 0,
        "Bwd Header Len": 0,

        "Fwd Pkts/s": 0,
        "Bwd Pkts/s": 0,

        "Pkt Len Min": np.min(lengths),
        "Pkt Len Max": np.max(lengths),
        "Pkt Len Mean": np.mean(lengths),
        "Pkt Len Std": np.std(lengths),
        "Pkt Len Var": np.var(lengths),

        "FIN Flag Cnt": 0,
        "SYN Flag Cnt": 0,
        "RST Flag Cnt": 0,
        "PSH Flag Cnt": 0,
        "ACK Flag Cnt": 0,
        "URG Flag Cnt": 0,

        "CWE Flag Count": 0,
        "ECE Flag Cnt": 0,

        "Down/Up Ratio": 0,
        "Pkt Size Avg": np.mean(lengths),

        "Fwd Seg Size Avg": np.mean(lengths),
        "Bwd Seg Size Avg": 0,

        "Fwd Byts/b Avg": 0,
        "Fwd Pkts/b Avg": 0,
        "Fwd Blk Rate Avg": 0,
        "Bwd Byts/b Avg": 0,
        "Bwd Pkts/b Avg": 0,
        "Bwd Blk Rate Avg": 0,

        "Subflow Fwd Pkts": len(pkts),
        "Subflow Fwd Byts": sum(lengths),
        "Subflow Bwd Pkts": 0,
        "Subflow Bwd Byts": 0,

        "Init Fwd Win Byts": 0,
        "Init Bwd Win Byts": 0,

        "Fwd Act Data Pkts": 0,
        "Fwd Seg Size Min": np.min(lengths),

        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,

        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0,

        "Label": "BENIGN"
    }

    rows.append(row)

df = pd.DataFrame(rows)

print("💾 Saving CSV...")
df.to_csv(OUTPUT_PATH, index=False)

print("✅ Done! Saved:", OUTPUT_PATH)