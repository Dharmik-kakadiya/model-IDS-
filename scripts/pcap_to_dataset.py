import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

PCAP_FILE = "../scripts/benign_real_traffic.pcap"
OUTPUT_FILE = "../data/benign_real_dataset.csv"

print("📂 Reading PCAP...")

packets = rdpcap(PCAP_FILE)

flows = defaultdict(lambda: {
    "Dst Port":0,
    "Protocol":0,
    "Tot Fwd Pkts":0,
    "Tot Bwd Pkts":0,
    "TotLen Fwd Pkts":0,
    "TotLen Bwd Pkts":0
})

print("🔄 Building flows...")

for pkt in packets:

    if IP not in pkt:
        continue

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto

    sport = 0
    dport = 0

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    key = (src, dst, sport, dport, proto)

    flows[key]["Dst Port"] = dport
    flows[key]["Protocol"] = proto
    flows[key]["Tot Fwd Pkts"] += 1
    flows[key]["TotLen Fwd Pkts"] += len(pkt)

print("📊 Converting to dataframe...")

data = []

for k,v in flows.items():
    row = v.copy()
    row["Label"] = "BENIGN"
    data.append(row)

df = pd.DataFrame(data)

print("💾 Saving dataset...")

df.to_csv(OUTPUT_FILE, index=False)

print("✅ Dataset Created:", OUTPUT_FILE)