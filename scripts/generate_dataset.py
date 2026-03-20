import pandas as pd
import os

DATA_DIR = "../data"
OUTPUT_FILE = "../data/final_dataset.csv"

print("📂 Scanning dataset folder...")

frames = []

for file in os.listdir(DATA_DIR):

    if file.endswith(".csv") and file != "final_dataset.csv":

        path = os.path.join(DATA_DIR, file)

        print("Loading:", file)

        df = pd.read_csv(path, low_memory=False)

        frames.append(df)

dataset = pd.concat(frames)

print("Total Rows:", len(dataset))

dataset.to_csv(OUTPUT_FILE, index=False)

print("✅ Dataset saved:", OUTPUT_FILE)