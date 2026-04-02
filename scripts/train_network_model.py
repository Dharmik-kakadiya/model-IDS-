import os
import warnings
import pandas as pd
import numpy as np
import joblib

# Suppress internal sklearn/joblib version mismatch warning (not user code issue)
warnings.filterwarnings(
    "ignore",
    message="`sklearn.utils.parallel.delayed` should be used",
    category=UserWarning,
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODEL_DIR, exist_ok=True)

# =============================
# SETTINGS
# =============================

SAMPLE_PER_FILE = 80000       # rows to sample from each CSV
DROP_COLUMNS = ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Src Port"]
TEST_SIZE = 0.2
RANDOM_STATE = 42

# =============================
# COLUMN MAPPING (2017 -> 2018)
# =============================

COLUMN_MAP_2017_TO_2018 = {
    "Destination Port": "Dst Port",
    "Total Fwd Packets": "Tot Fwd Pkts",
    "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max",
    "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
    "Fwd IAT Total": "Fwd IAT Tot",
    "Bwd IAT Total": "Bwd IAT Tot",
    "Fwd Header Length": "Fwd Header Len",
    "Bwd Header Length": "Bwd Header Len",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Bwd Packets/s": "Bwd Pkts/s",
    "Min Packet Length": "Pkt Len Min",
    "Max Packet Length": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean",
    "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt",
    "SYN Flag Count": "SYN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "URG Flag Count": "URG Flag Cnt",
    "ECE Flag Count": "ECE Flag Cnt",
    "Average Packet Size": "Pkt Size Avg",
    "Avg Fwd Segment Size": "Fwd Seg Size Avg",
    "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "Fwd Header Length.1": "Fwd Header Len",
    "Fwd Avg Bytes/Bulk": "Fwd Byts/b Avg",
    "Fwd Avg Packets/Bulk": "Fwd Pkts/b Avg",
    "Fwd Avg Bulk Rate": "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk": "Bwd Byts/b Avg",
    "Bwd Avg Packets/Bulk": "Bwd Pkts/b Avg",
    "Bwd Avg Bulk Rate": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "Init_Win_bytes_forward": "Init Fwd Win Byts",
    "Init_Win_bytes_backward": "Init Bwd Win Byts",
    "act_data_pkt_fwd": "Fwd Act Data Pkts",
    "min_seg_size_forward": "Fwd Seg Size Min",
}

def normalize_columns(df):
    """Strip whitespace from column names and rename 2017 columns to 2018 format."""
    df.columns = df.columns.str.strip()
    df = df.rename(columns=COLUMN_MAP_2017_TO_2018)
    # drop duplicate columns if any (e.g. Fwd Header Length.1)
    df = df.loc[:, ~df.columns.duplicated(keep='first')]
    return df

# =============================
# STEP 1: LOAD & SAMPLE DATA
# =============================

print("Loading and sampling data from CSV files...")

all_chunks = []

for file in sorted(os.listdir(DATA_DIR)):

    if not file.endswith(".csv"):
        continue

    file_path = os.path.join(DATA_DIR, file)
    print(f"  Reading: {file}")

    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"  Skipped {file}: {e}")
        continue

    # normalize column names (handles 2017 vs 2018 format)
    df = normalize_columns(df)

    # drop non-numeric identifiers
    df = df.drop(columns=DROP_COLUMNS, errors="ignore")

    # fix bad values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    if df.empty:
        continue

    # sample rows to keep memory manageable
    if len(df) > SAMPLE_PER_FILE:
        df = df.sample(SAMPLE_PER_FILE, random_state=RANDOM_STATE)

    all_chunks.append(df)
    print(f"    Sampled {len(df)} rows | Benign: {(df['Label'].str.upper()=='BENIGN').sum()} | Attack: {(df['Label'].str.upper()!='BENIGN').sum()}")

# =============================
# STEP 2: COMBINE & BALANCE
# =============================

print("\nCombining all data...")
data = pd.concat(all_chunks, ignore_index=True)
del all_chunks

print(f"Total rows: {len(data)}")

# create label
data["Label_Binary"] = data["Label"].apply(lambda x: 0 if str(x).upper() == "BENIGN" else 1)

benign = data[data["Label_Binary"] == 0]
attack = data[data["Label_Binary"] == 1]

print(f"Before balancing -> Benign: {len(benign)} | Attack: {len(attack)}")

# balance: undersample benign to 10x attack count (closer to real-world ratio)
if len(benign) > len(attack) * 10:
    benign = benign.sample(len(attack) * 10, random_state=RANDOM_STATE)

data = pd.concat([benign, attack], ignore_index=True)
data = data.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)  # shuffle

print(f"After balancing  -> Benign: {(data['Label_Binary']==0).sum()} | Attack: {(data['Label_Binary']==1).sum()}")
print(f"Total training rows: {len(data)}")

# =============================
# STEP 3: PREPARE FEATURES
# =============================

y = data["Label_Binary"]
X = data.drop(columns=["Label", "Label_Binary"])

# numeric conversion
X = X.apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], 0)
X = X.clip(-1e10, 1e10)
X = X.fillna(0)

FEATURE_COLUMNS = X.columns.tolist()
print(f"\nFeatures: {len(FEATURE_COLUMNS)}")

# =============================
# STEP 4: SCALE
# =============================

print("Scaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# =============================
# STEP 5: TRAIN/TEST SPLIT
# =============================

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
)

print(f"Train: {len(X_train)} | Test: {len(X_test)}")

# =============================
# STEP 6: TRAIN MODEL
# =============================

print("\nTraining RandomForest model...")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,           # reduced from 30 to limit overfitting
    min_samples_split=5,
    min_samples_leaf=5,     # raised from 2 for better generalisation
    class_weight="balanced",     # auto: sklearn computes weights from class distribution
    random_state=RANDOM_STATE,
    n_jobs=-1,
    verbose=0
)

model.fit(X_train, y_train)

# =============================
# STEP 7: EVALUATE ON TEST SET
# =============================

print("\n--- TEST SET RESULTS ---\n")

y_pred = model.predict(X_test)

print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"\nClassification Report:\n")
print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

# =============================
# STEP 8: SAVE
# =============================

joblib.dump(model, os.path.join(MODEL_DIR, "network_model.pkl"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
joblib.dump(FEATURE_COLUMNS, os.path.join(MODEL_DIR, "features.pkl"))

print("Model saved successfully!")