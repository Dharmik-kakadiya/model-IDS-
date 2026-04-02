# 🛡️ Network IDS — Complete System Flow Diagram

## 🔄 Poora System Flow (Training + Live Detection)

```mermaid
flowchart TD
    %% ─── DATA SOURCES ───
    subgraph DS["📦 DATA SOURCES"]
        D1["🗂️ CICIDS 2017 Dataset\n(CSV Files)"]
        D2["🗂️ CICIDS 2018 Dataset\n(CSV Files)"]
        D3["🌐 Live Network Traffic\n(Scapy Packet Sniffer)"]
    end

    %% ─── TRAINING PIPELINE ───
    subgraph TP["🧠 TRAINING PIPELINE  —  train_network_model.py"]
        T1["📥 Data Load\n80,000 rows/file sample"]
        T2["⚖️ Class Balancing\nBenign : Attack = 10:1\nUndersampling"]
        T3["🧹 Feature Engineering\n~70 Numeric Features\nDrop: IP, Timestamps"]
        T4["📐 StandardScaler\nFeature Normalization"]
        T5["🌲 RandomForestClassifier\n300 Trees | max_depth=20\n80% Train / 20% Test"]
        T6["💾 Save Models"]
    end

    %% ─── SAVED MODELS ───
    subgraph MD["💾 SAVED MODELS  —  /models/"]
        M1["🌲 network_model.pkl\nRandom Forest\n(187 MB)"]
        M2["📐 scaler.pkl\nStandardScaler"]
        M3["📋 features.pkl\nFeature Column List"]
        M4["🔤 flag_encoder.pkl\nFlag Label Encoder"]
        M5["🔤 protocol_encoder.pkl\nProtocol Label Encoder"]
    end

    %% ─── EVALUATION ───
    subgraph EV["📊 EVALUATION  —  evalute_model.py"]
        E1["📂 Load Test Data"]
        E2["🔢 Load Models\n(model + scaler + features)"]
        E3["📈 Report\nAccuracy, Precision\nRecall, F1-Score"]
        E4["🎯 Threshold Tuning\nBest threshold for\nyour network data"]
    end

    %% ─── LIVE FLOW TRACKING ───
    subgraph FT["🔍 FLOW TRACKING  —  flow_state.py"]
        F1["📡 Packet Capture\nScapy sniff()"]
        F2["🔀 ARP Spoofing\nMITM — all LAN traffic\nrouted through IDS machine"]
        F3["📊 Flow Aggregation\nSrc IP → Dst IP + Port + Protocol\nFLOW_TIMEOUT = 2 sec"]
        F4["📐 Feature Extraction\n~70 features per flow\nDuration, Bytes/s, Flags..."]
    end

    %% ─── LIVE DETECTION ───
    subgraph LD["🚨 LIVE DETECTION ENGINE"]
        L1["🔄 Load Saved Models\nmodel + scaler + features\n+ encoders"]
        L2["📐 Scale Features\nStandardScaler.transform()"]
        L3["🌲 RF Predict\npredict_proba()"]
        L4{"⚖️ Threshold Check\nATTACK_THRESHOLD = 0.90"}
        L5["✅ BENIGN\nattack_prob ≤ 0.90"]
        L6["🚨 ATTACK ALERT\nattack_prob > 0.90"]
    end

    %% ─── OUTPUT MODES ───
    subgraph OUT["🖥️ OUTPUT / MONITORING"]
        O1["📟 live_ids.py\nSimple Line-by-Line\nConsole Output"]
        O2["📊 network_dashboard.py\nReal-time Table Dashboard\nDevice Discovery + Stats"]
        O3["📡 Device Summary\nMAC | IP | Hostname\nFirst Seen | Pkt Count"]
    end

    %% ─── CONNECTIONS ───

    D1 --> T1
    D2 --> T1

    T1 --> T2
    T2 --> T3
    T3 --> T4
    T4 --> T5
    T5 --> T6

    T6 --> M1
    T6 --> M2
    T6 --> M3
    T6 --> M4
    T6 --> M5

    M1 --> E2
    M2 --> E2
    M3 --> E2
    E1 --> E2
    E2 --> E3
    E3 --> E4

    D3 --> F1
    F1 --> F2
    F2 --> F3
    F3 --> F4

    M1 --> L1
    M2 --> L1
    M3 --> L1
    M4 --> L1
    M5 --> L1

    F4 --> L2
    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 -->|"≤ 0.90"| L5
    L4 -->|"> 0.90"| L6

    L5 --> O1
    L6 --> O1
    L5 --> O2
    L6 --> O2
    O2 --> O3

    %% ─── STYLES ───
    style DS fill:#1a1a2e,stroke:#4a90d9,color:#ffffff
    style TP fill:#16213e,stroke:#f39c12,color:#ffffff
    style MD fill:#0f3460,stroke:#e74c3c,color:#ffffff
    style EV fill:#1a1a2e,stroke:#2ecc71,color:#ffffff
    style FT fill:#16213e,stroke:#9b59b6,color:#ffffff
    style LD fill:#0f3460,stroke:#e74c3c,color:#ffffff
    style OUT fill:#1a1a2e,stroke:#1abc9c,color:#ffffff

    style M1 fill:#8e1538,stroke:#e74c3c,color:#ffffff
    style M2 fill:#8e1538,stroke:#e74c3c,color:#ffffff
    style M3 fill:#8e1538,stroke:#e74c3c,color:#ffffff
    style M4 fill:#8e1538,stroke:#e74c3c,color:#ffffff
    style M5 fill:#8e1538,stroke:#e74c3c,color:#ffffff

    style L6 fill:#c0392b,stroke:#e74c3c,color:#ffffff
    style L5 fill:#1e8449,stroke:#2ecc71,color:#ffffff
    style L4 fill:#7d6608,stroke:#f39c12,color:#ffffff
```

---

## 📋 Models Ka Role — Quick Summary

| Model File | Type | Kaam |
|---|---|---|
| `network_model.pkl` | RandomForestClassifier (300 trees) | Traffic ko BENIGN/ATTACK classify karta hai |
| `scaler.pkl` | StandardScaler | Features ko normalize karta hai (same range) |
| `features.pkl` | Feature List | Ensure karta hai ki sahi 70 columns use hon |
| `flag_encoder.pkl` | LabelEncoder | TCP flags (SYN, ACK…) ko number mein convert |
| `protocol_encoder.pkl` | LabelEncoder | Protocol (TCP/UDP/ICMP) ko number mein convert |

---

## 🚦 Decision Logic

```mermaid
flowchart LR
    A["🌐 Live\nNetwork Packet"] --> B["flow_state.py\nFlow Aggregation\n2 sec window"]
    B --> C["~70 Features\nExtract karo"]
    C --> D["scaler.pkl\nNormalize"]
    D --> E["network_model.pkl\npredict_proba()"]
    E --> F{"attack_prob\n> 0.90?"}
    F -->|"YES"| G["🚨 ATTACK!\nAlert print karo"]
    F -->|"NO"| H["✅ BENIGN\nNormal log"]

    style A fill:#2c3e50,stroke:#3498db,color:#fff
    style B fill:#2c3e50,stroke:#9b59b6,color:#fff
    style C fill:#2c3e50,stroke:#f39c12,color:#fff
    style D fill:#8e1538,stroke:#e74c3c,color:#fff
    style E fill:#8e1538,stroke:#e74c3c,color:#fff
    style F fill:#7d6608,stroke:#f1c40f,color:#fff
    style G fill:#c0392b,stroke:#e74c3c,color:#fff
    style H fill:#1e8449,stroke:#2ecc71,color:#fff
```

---

## 🗂️ Script → Model Dependency Map

```mermaid
flowchart LR
    S1["train_network_model.py"] -->|"Creates"| M1["network_model.pkl"]
    S1 -->|"Creates"| M2["scaler.pkl"]
    S1 -->|"Creates"| M3["features.pkl"]
    S1 -->|"Creates"| M4["flag_encoder.pkl"]
    S1 -->|"Creates"| M5["protocol_encoder.pkl"]

    S2["evalute_model.py"] -->|"Loads"| M1
    S2 -->|"Loads"| M2
    S2 -->|"Loads"| M3

    S3["live_ids.py"] -->|"Loads"| M1
    S3 -->|"Loads"| M2
    S3 -->|"Loads"| M3
    S3 -->|"Loads"| M4
    S3 -->|"Loads"| M5
    S3 -->|"Uses"| S4["flow_state.py"]

    S5["network_dashboard.py"] -->|"Loads"| M1
    S5 -->|"Loads"| M2
    S5 -->|"Loads"| M3
    S5 -->|"Loads"| M4
    S5 -->|"Loads"| M5
    S5 -->|"Uses"| S4

    style M1 fill:#8e1538,stroke:#e74c3c,color:#fff
    style M2 fill:#8e1538,stroke:#e74c3c,color:#fff
    style M3 fill:#8e1538,stroke:#e74c3c,color:#fff
    style M4 fill:#8e1538,stroke:#e74c3c,color:#fff
    style M5 fill:#8e1538,stroke:#e74c3c,color:#fff
    style S1 fill:#1a472a,stroke:#2ecc71,color:#fff
    style S2 fill:#1a3a5c,stroke:#3498db,color:#fff
    style S3 fill:#4a235a,stroke:#9b59b6,color:#fff
    style S4 fill:#4a235a,stroke:#9b59b6,color:#fff
    style S5 fill:#4a235a,stroke:#9b59b6,color:#fff
```
