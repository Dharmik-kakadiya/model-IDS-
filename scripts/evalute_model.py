import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# =============================
# PATH SETUP
# =============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH   = os.path.join(BASE_DIR, "models", "network_model.pkl")
SCALER_PATH  = os.path.join(BASE_DIR, "models", "scaler.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "models", "features.pkl")

# Use a test file for evaluation
DATA_PATH = os.path.join(BASE_DIR, "data", "Thursday-22-02-2018.csv")

DROP_COLUMNS = ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Src Port"]

print("Loading model...")
model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
features = joblib.load(FEATURES_PATH)

print("Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

df.columns = df.columns.str.strip()

print("Original Shape:", df.shape)

# =============================
# CLEAN DATA
# =============================

df = df.drop(columns=DROP_COLUMNS, errors="ignore")
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

print("After Cleaning:", df.shape)

# =============================
# LABEL
# =============================

y_labels = df["Label"]
y = y_labels.apply(lambda x: 0 if str(x).upper() == "BENIGN" else 1)
X = df.drop(columns=["Label"])

X = X.apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], 0)
X = X.clip(-1e10, 1e10)
X = X.fillna(0)

# Align features to match training
X = X.reindex(columns=features, fill_value=0)

# =============================
# SCALE + PREDICT PROBABILITIES
# =============================

print("Scaling...")
X_scaled = scaler.transform(X)

print("Predicting probabilities...")
y_prob = model.predict_proba(X_scaled)[:, 1]   # probability of ATTACK

# =============================
# DEFAULT THRESHOLD RESULTS (0.5)
# =============================

print("\n" + "="*55)
print("        MODEL PERFORMANCE REPORT  (threshold=0.50)")
print("="*55)

y_pred_default = (y_prob >= 0.5).astype(int)
print(f"\nAccuracy : {accuracy_score(y, y_pred_default):.4f}")
print(f"\nClassification Report:\n")
print(classification_report(y, y_pred_default, target_names=["BENIGN", "ATTACK"]))

cm = confusion_matrix(y, y_pred_default)
print("Confusion Matrix:\n", cm)
tn, fp, fn, tp = cm.ravel()
print(f"\n  True Negatives  (Benign correctly):  {tn}")
print(f"  False Positives (Benign as Attack):   {fp}")
print(f"  False Negatives (Attack missed):      {fn}")
print(f"  True Positives  (Attack caught):      {tp}")

total_attacks = fn + tp
total_benign  = tn + fp
if total_attacks > 0:
    print(f"\n  Attack Detection Rate: {tp}/{total_attacks} = {tp/total_attacks*100:.1f}%")
if total_benign > 0:
    print(f"  False Alarm Rate:      {fp}/{total_benign} = {fp/total_benign*100:.1f}%")

# =============================
# THRESHOLD SWEEP
# =============================

print("\n" + "="*55)
print("   THRESHOLD SWEEP — Finding the Sweet Spot")
print("="*55)
print(f"\n{'Threshold':>10} | {'Detection%':>10} | {'FalseAlarm%':>11} | {'Precision':>9} | {'F1(Attack)':>10}")
print("-"*60)

thresholds = [0.5, 0.4, 0.3, 0.2, 0.15, 0.1, 0.05]

best_thresh = 0.5
best_f1 = 0.0

for thresh in thresholds:
    y_pred_t = (y_prob >= thresh).astype(int)
    cm_t = confusion_matrix(y, y_pred_t)
    tn_t, fp_t, fn_t, tp_t = cm_t.ravel()

    detection   = tp_t / (fn_t + tp_t) * 100 if (fn_t + tp_t) > 0 else 0
    false_alarm = fp_t / (tn_t + fp_t) * 100 if (tn_t + fp_t) > 0 else 0
    precision   = tp_t / (tp_t + fp_t) * 100  if (tp_t + fp_t) > 0 else 0

    # F1 for attack class
    if (precision + detection) > 0:
        f1 = 2 * precision * detection / (precision + detection)
    else:
        f1 = 0.0

    marker = " <-- BEST" if f1 > best_f1 else ""
    if f1 > best_f1:
        best_f1 = f1
        best_thresh = thresh

    print(f"{thresh:>10.2f} | {detection:>9.1f}% | {false_alarm:>10.1f}% | {precision:>8.1f}% | {f1:>9.1f}%{marker}")

print(f"\n[BEST] Recommended threshold: {best_thresh}  (best F1 score for attack class)")
print("\nTo use this in production, set:")
print(f"   y_pred = (model.predict_proba(X)[:, 1] >= {best_thresh}).astype(int)")