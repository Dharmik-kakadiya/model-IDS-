import sys
import os
import subprocess

# Enable terminal colors and fix unicode on Windows
if sys.platform == "win32":
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Colors for beautiful output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

# List of required packages
REQUIRED_PACKAGES = [
    "scapy",
    "joblib",
    "pandas",
    "numpy",
    "scikit-learn",
    "rich"
]

def is_installed(package_name):
    """Check if a package is installed using pip."""
    try:
        # Run 'pip show <package_name>' silently
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", package_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False

def install_package(package_name):
    """Install a package using pip."""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║            NetGuard IDS - Package Installer Script           ║{RESET}")
    print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"Checking and installing dependencies...\n")

    all_success = True

    for pkg in REQUIRED_PACKAGES:
        # Check if already installed
        if is_installed(pkg):
            print(f"📦 {pkg:<15} {GREEN}[ALREADY INSTALLED]{RESET}")
        else:
            print(f"📦 {pkg:<15} {YELLOW}[INSTALLING...]{RESET}", end="", flush=True)
            
            # Try installing
            success = install_package(pkg)
            
            if success:
                # Clear the "[INSTALLING...]" text and replace with success
                print(f"\r📦 {pkg:<15} {GREEN}[SUCCESSFULLY INSTALLED]{RESET}   ")
            else:
                print(f"\r📦 {pkg:<15} {RED}[FAILED TO INSTALL]{RESET}        ")
                all_success = False

    print(f"\n{CYAN}────────────────────────────────────────────────────────────────{RESET}")
    
    if all_success:
        print(f"{GREEN}{BOLD}✓ Setup Complete! All packages are installed and ready.{RESET}")
        print(f"  You can now start the IDS by running:{RESET}")
        print(f"  {YELLOW}cd scripts && python live_ids_auto.py{RESET}")
    else:
        print(f"{RED}{BOLD}✗ Some packages failed to install. Please check your internet.{RESET}")
        
    print(f"{CYAN}────────────────────────────────────────────────────────────────{RESET}\n")

if __name__ == "__main__":
    main()
