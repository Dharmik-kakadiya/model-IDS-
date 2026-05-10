import os
import re

readme_path = "README.md"
with open(readme_path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix evalute_model.py
content = content.replace("evalute_model.py", "evaluate_model.py")

# Fix pip install
content = content.replace("pip install scapy joblib pandas numpy scikit-learn rich netifaces", "pip install scapy joblib pandas numpy scikit-learn rich netifaces2")

# Windows-only declaration
content = content.replace("# 🛡️ NetGuardIDS", "# 🛡️ NetGuardIDS (Windows-Only)")

# live_ids_auto.py vs live_ids.py confusion
# replace "live_ids.py — Main live IDS (recommended)" with "live_ids_auto.py — Main live IDS (recommended)"
content = content.replace("live_ids.py — Main live IDS", "live_ids_auto.py — Main live IDS")
content = content.replace("### `live_ids.py`\n\n**Main production IDS script.**", "### `live_ids_auto.py`\n\n**Main production IDS script.**")
content = content.replace("### `live_ids.py` Settings", "### `live_ids_auto.py` Settings")
content = content.replace("python scripts/live_ids.py", "python scripts/live_ids_auto.py")

# Add dataset download instructions
dataset_text = """## Datasets

Stored in `data/`. You must create this folder and download datasets manually.

### Download Instructions:
1. Create a `data/` directory in the project root.
2. Download CICIDS 2017/2018 or CTU-13 dataset CSV files from the Canadian Institute for Cybersecurity (UNB) or relevant sources.
3. Place the CSV files inside the `data/` directory.

"""
content = re.sub(r'## Datasets\n\nStored in `data/`. Large CSV files — not tracked by Git.\n', dataset_text, content)

# Remove benign_traffic.pcap from scripts
content = content.replace("    ├── benign_traffic.pcap     ← Sample benign traffic capture file\n", "")
content = content.replace("│   ├── final_dataset.csv              (merged, pre-processed)\n│   └── ...\n", "│   ├── final_dataset.csv              (merged, pre-processed)\n│   ├── benign_traffic.pcap            ← Sample benign traffic capture file\n│   └── ...\n")

# Add missing scripts to Script Reference
missing_scripts = """
---

### `verify_setup.py`

**Utility script.** Verifies the installation, dependencies, and NPcap driver status. Run this if you face any issues starting the IDS.

---

### `pcap_to_dataset.py`

**Utility script.** Converts raw `.pcap` files into training dataset CSV format.

---

### `generate_dataset.py`

**Utility script.** Helper for dataset generation from captured flows.

"""
content = content.replace("### `pcap_to_flow.py`\n\n**Utility script.** Reads a `.pcap` file", missing_scripts + "### `pcap_to_flow.py`\n\n**Utility script.** Reads a `.pcap` file")


# Extract model_guide.md and CHANGELOG.md
parts = content.split("*Documentation generated for IDS Model project — March 2026.*\n\n\n# 🛡 Network IDS — Model Ki Poori Jaankari")

if len(parts) == 2:
    readme_main = parts[0] + "*Documentation generated for IDS Model project — March 2026.*\n"
    rest = "# 🛡 Network IDS — Model Ki Poori Jaankari" + parts[1]
    
    parts2 = rest.split("\n\n# NetGuardIDS - Project Updates & Bug Fixes")
    if len(parts2) == 2:
        model_guide = parts2[0]
        changelog = "# NetGuardIDS - Project Updates & Bug Fixes" + parts2[1]
        
        with open("model_guide.md", "w", encoding="utf-8") as f:
            f.write(model_guide)
        with open("CHANGELOG.md", "w", encoding="utf-8") as f:
            f.write(changelog)
            
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(readme_main)

print("Done fixing docs")
