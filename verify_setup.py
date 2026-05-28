import sys
import os

# Force UTF-8 output so Unicode chars work on Windows terminals
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import platform
import importlib
import subprocess
import struct
from pathlib import Path

# ──────────────────────────────────────────────
# Colour helpers  (no external deps needed)
# ──────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Enable ANSI on Windows 10+
if sys.platform == "win32":
    os.system("color")

def ok(msg):    print(f"  {GREEN}[OK]{RESET}      {msg}")
def warn(msg):  print(f"  {YELLOW}[WARN]{RESET}    {msg}")
def err(msg):   print(f"  {RED}[FAIL]{RESET}    {msg}")
def info(msg):  print(f"  {CYAN}[INFO]{RESET}    {msg}")
def section(title):
    print(f"\n{BOLD}{'-'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'-'*60}{RESET}")

PASS = 0
FAIL = 0

def check(condition, ok_msg, fail_msg, is_warning=False):
    global PASS, FAIL
    if condition:
        ok(ok_msg)
        PASS += 1
    else:
        if is_warning:
            warn(fail_msg)
        else:
            err(fail_msg)
            FAIL += 1


# ══════════════════════════════════════════════
# 1. SYSTEM INFO
# ══════════════════════════════════════════════
section("1 / 6  —  System Information")

info(f"OS          : {platform.system()} {platform.release()} ({platform.version()})")
info(f"Architecture: {platform.machine()}")
info(f"Python      : {sys.version}")
info(f"Executable  : {sys.executable}")

py_major, py_minor = sys.version_info[:2]
check(
    py_major == 3 and py_minor >= 9,
    f"Python {py_major}.{py_minor} ≥ 3.9  ✓",
    f"Python {py_major}.{py_minor} detected — NetGuardIDS needs Python 3.9+",
)

# 64-bit check (some packages behave differently on 32-bit)
check(
    struct.calcsize("P") == 8,
    "64-bit Python  ✓",
    "32-bit Python detected — prefer 64-bit for ML workloads",
    is_warning=True,
)


# ══════════════════════════════════════════════
# 2. REQUIRED PACKAGES
# ══════════════════════════════════════════════
section("2 / 6  —  Python Package Check")

REQUIRED = {
    "scapy":        ("scapy",        "2.5.0"),
    "joblib":       ("joblib",       "1.2.0"),
    "pandas":       ("pandas",       "1.5.0"),
    "numpy":        ("numpy",        "1.23.0"),
    "sklearn":      ("scikit-learn", "1.2.0"),
    "rich":         ("rich",         "13.0.0"),
}

# netifaces has no Python 3.12+ wheel; netifaces2 is the drop-in replacement.
OPTIONAL_NETIFACES = True   # checked separately below

for import_name, (pip_name, min_ver) in REQUIRED.items():
    try:
        mod = importlib.import_module(import_name)
        ver = getattr(mod, "__version__", "unknown")
        ok(f"{pip_name:<20}  installed  (version: {ver})")
        PASS += 1
    except ImportError:
        err(f"{pip_name:<20}  NOT FOUND  →  pip install {pip_name}")
        FAIL += 1


# ══════════════════════════════════════════════
# 3. NPCAP / WINPCAP  (Windows packet capture driver)
# ══════════════════════════════════════════════
if sys.platform == "win32":
    section("3 / 6  —  Npcap Driver Check")

    npcap_paths = [
        r"C:\Program Files\Npcap\npcap.sys",
        r"C:\Windows\System32\Npcap\npcap.sys",
        r"C:\Windows\SysWOW64\Npcap\npcap.sys",
        r"C:\Program Files\WinPcap\wpcap.dll",   # legacy fallback
    ]
    npcap_found = any(Path(p).exists() for p in npcap_paths)
    check(
        npcap_found,
        "Npcap (or WinPcap) driver is installed  ✓",
        "Npcap NOT found!  Download from https://npcap.com/#download\n"
        "           During install: check 'WinPcap API-compatible Mode'",
    )

    # Try actually importing scapy's layer that talks to Npcap
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        check(
            len(ifaces) > 0,
            f"Scapy can enumerate {len(ifaces)} network interface(s)  ✓",
            "Scapy found 0 interfaces — Npcap may not be installed correctly",
        )
    except Exception as e:
        warn(f"Could not query interfaces via Scapy: {e}")
else:
    section("3 / 6  —  libpcap Check (Linux/macOS)")
    result = subprocess.run(["python", "-c", "from scapy.all import conf; print(conf.iface)"],
                            capture_output=True, text=True)
    check(result.returncode == 0,
          "Scapy can access network interfaces  ✓",
          f"Scapy interface error: {result.stderr.strip()}")


# ══════════════════════════════════════════════
# 4. MODEL FILES
# ══════════════════════════════════════════════
section("4 / 6  —  Model Files Check")

BASE_DIR   = Path(__file__).parent
MODEL_DIR  = BASE_DIR / "models"
SCRIPT_DIR = BASE_DIR / "scripts"

files_to_check = {
    "network_model.pkl" : (MODEL_DIR  / "network_model.pkl",  50_000_000),  # ~50 MB minimum
    "scaler.pkl"        : (MODEL_DIR  / "scaler.pkl",         100),
    "features.pkl"      : (MODEL_DIR  / "features.pkl",       100),
    "live_ids_auto.py"  : (SCRIPT_DIR / "live_ids_auto.py",   1_000),
    "flow_state.py"     : (SCRIPT_DIR / "flow_state.py",      500),
}

for label, (path, min_bytes) in files_to_check.items():
    if path.exists():
        size = path.stat().st_size
        size_kb = size / 1024
        size_mb = size_kb / 1024
        size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{size_kb:.1f} KB"
        
        if label == "network_model.pkl" and size < 1024:
            err(f"{label:<22}  Git LFS Error! File is only {size} bytes.")
            err(f"{' ':>24}  You downloaded a GitHub ZIP which lacks the real 187MB file.")
            err(f"{' ':>24}  This causes 'KeyError 118' when running the script.")
            err(f"{' ':>24}  Fix: Download the raw network_model.pkl directly from GitHub.")
            FAIL += 1
            continue

        check(
            size >= min_bytes,
            f"{label:<22}  Found  ({size_str})",
            f"{label:<22}  File exists but seems too small ({size_str}) — may be corrupted",
            is_warning=True,
        )
    else:
        err(f"{label:<22}  NOT FOUND at: {path}")
        FAIL += 1


# ══════════════════════════════════════════════
# 5. MODEL LOAD TEST  (actual joblib load)
# ══════════════════════════════════════════════
section("5 / 6  —  Model Load Test")

model_path  = MODEL_DIR / "network_model.pkl"
scaler_path = MODEL_DIR / "scaler.pkl"

if model_path.exists() and scaler_path.exists():
    try:
        import joblib
        info("Loading model... (this may take a few seconds)")
        model = joblib.load(str(model_path))
        ok("network_model.pkl  loaded successfully")
        PASS += 1

        scaler = joblib.load(str(scaler_path))
        ok("scaler.pkl  loaded successfully")
        PASS += 1

        # Check feature count
        if hasattr(scaler, "feature_names_in_"):
            n_feat = len(scaler.feature_names_in_)
            ok(f"Model expects {n_feat} features  ✓")
            PASS += 1
        else:
            warn("Could not determine feature count from scaler")

        # Quick predict test
        import numpy as np
        import pandas as pd
        cols   = list(scaler.feature_names_in_) if hasattr(scaler, "feature_names_in_") else []
        if cols:
            dummy  = pd.DataFrame([{c: 0.0 for c in cols}])
            scaled = scaler.transform(dummy)
            prob   = model.predict_proba(scaled)[0]
            ok(f"Dry-run prediction succeeded  (prob={prob})  ✓")
            PASS += 1
        else:
            info("Skipping dry-run prediction — feature list unavailable")

    except Exception as e:
        err(f"Model load failed: {e}")
        FAIL += 1
else:
    warn("Skipping model load test — one or more model files missing")


# ══════════════════════════════════════════════
# 6. NETWORK INTERFACES
# ══════════════════════════════════════════════
section("6 / 6  —  Network Interfaces")

# Try netifaces first, then netifaces2 (Python 3.12+ replacement)
_netifaces = None
for _mod_name in ("netifaces", "netifaces2"):
    try:
        _netifaces = importlib.import_module(_mod_name)
        ok(f"{_mod_name}  available  ✓")
        PASS += 1
        break
    except ImportError:
        pass

if _netifaces is None:
    err("Neither netifaces nor netifaces2 found.")
    info("  Fix:  pip install netifaces2")
    FAIL += 1
else:
    try:
        iface_list  = _netifaces.interfaces()
        AF_INET     = _netifaces.AF_INET
        real_ifaces = []
        for iface in iface_list:
            addrs = _netifaces.ifaddresses(iface)
            if AF_INET in addrs:
                ip = addrs[AF_INET][0].get("addr", "")
                if ip and not ip.startswith("127."):
                    real_ifaces.append((iface, ip))
        if real_ifaces:
            ok(f"Found {len(real_ifaces)} active network interface(s):")
            for name, ip in real_ifaces:
                info(f"  {name:<40}  IP: {ip}")
        else:
            warn("No active non-loopback interfaces found")
    except Exception as e:
        warn(f"Interface enumeration failed: {e}")


# ══════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════
try:
    sys.stdout.reconfigure(encoding='utf-8')
except:
    pass

print(f"\n{'='*60}")
print(f"{BOLD}  VERIFICATION REPORT{RESET}")
print(f"{'='*60}")
print(f"  {GREEN}Passed : {PASS}{RESET}")
print(f"{RED}  Failed : {FAIL}{RESET}")
print()

if FAIL == 0:
    print(f"{GREEN}{BOLD}  OK  Everything looks good! NetGuardIDS is ready.{RESET}")
    print()
    print("  +----------------------------------------------+")
    print("  |  Start the IDS (from project root):          |")
    print("  |                                              |")
    print("  |    cd scripts                                |")
    print("  |    python live_ids_auto.py                   |")
    print("  |                                              |")
    print("  |  Run as Administrator for full features!     |")
    print("  +----------------------------------------------+")
else:
    print(f"{RED}{BOLD}  X  {FAIL} check(s) failed. Fix the issues above, then re-run.{RESET}")
    print()
    print("  Tip: Run  setup.bat  (as Administrator) to auto-install")
    print("       all missing dependencies.")

print()
input("  Press Enter to exit...")
