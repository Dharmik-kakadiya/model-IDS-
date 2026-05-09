@echo off
chcp 65001 >nul
title NetGuardIDS - Setup & Configuration
color 0A

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║          NetGuardIDS — Automatic Setup Script               ║
echo ║          Network Intrusion Detection System                 ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: ───────────────────────────────────────────────
:: STEP 0: Check if running as Administrator
:: ───────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] This script is NOT running as Administrator.
    echo           Some features ^(Npcap install, IP forwarding^) need Admin rights.
    echo           Right-click this file and select "Run as Administrator".
    echo.
    pause
)

:: ───────────────────────────────────────────────
:: STEP 1: Check Python Installation
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 1/7] Checking Python installation...
echo ──────────────────────────────────────────────

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is NOT installed or not in PATH!
    echo.
    echo   ► Download Python from: https://www.python.org/downloads/
    echo   ► IMPORTANT: Check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

python --version
echo [OK] Python found!
echo.

:: ───────────────────────────────────────────────
:: STEP 2: Check pip
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 2/7] Checking pip...
echo ──────────────────────────────────────────────

python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] pip not found, installing...
    python -m ensurepip --upgrade
)
python -m pip install --upgrade pip
echo [OK] pip is ready!
echo.

:: ───────────────────────────────────────────────
:: STEP 3: Create Virtual Environment (Optional)
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 3/7] Virtual Environment Setup
echo ──────────────────────────────────────────────

if exist "venv\" (
    echo [INFO] Virtual environment already exists. Activating...
    call venv\Scripts\activate.bat
) else (
    echo Do you want to create a virtual environment? (Recommended)
    set /p CREATE_VENV="Type Y for Yes, N for No: "
    if /i "%CREATE_VENV%"=="Y" (
        echo [INFO] Creating virtual environment...
        python -m venv venv
        call venv\Scripts\activate.bat
        echo [OK] Virtual environment created and activated!
    ) else (
        echo [INFO] Skipping virtual environment. Installing globally...
    )
)
echo.

:: ───────────────────────────────────────────────
:: STEP 4: Install Python Dependencies
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 4/7] Installing Python dependencies...
echo ──────────────────────────────────────────────

echo [*] Installing: scapy (packet capture library)
pip install scapy

echo [*] Installing: joblib (model loading)
pip install joblib

echo [*] Installing: pandas (data processing)
pip install pandas

echo [*] Installing: numpy (numerical computing)
pip install numpy

echo [*] Installing: scikit-learn (ML model)
pip install scikit-learn

echo [*] Installing: rich (beautiful terminal output)
pip install rich

echo [*] Installing: netifaces (network interface detection)
pip install netifaces

echo.
echo [OK] All Python packages installed!
echo.

:: ───────────────────────────────────────────────
:: STEP 5: Check Npcap (Required for Scapy on Windows)
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 5/7] Checking Npcap (packet capture driver)...
echo ──────────────────────────────────────────────

if exist "C:\Program Files\Npcap\npcap.sys" (
    echo [OK] Npcap is already installed!
) else if exist "C:\Windows\System32\Npcap\npcap.sys" (
    echo [OK] Npcap is already installed!
) else (
    echo [WARNING] Npcap is NOT installed!
    echo.
    echo   Npcap is REQUIRED for packet capture on Windows.
    echo   Without it, the IDS cannot sniff network traffic.
    echo.
    echo   ► Download Npcap from: https://npcap.com/#download
    echo   ► During installation, CHECK these options:
    echo       ✓ "Install Npcap in WinPcap API-compatible Mode"
    echo       ✓ "Support raw 802.11 traffic"
    echo.
    echo   After installing Npcap, run this setup script again.
    echo.
    start https://npcap.com/#download
    pause
)
echo.

:: ───────────────────────────────────────────────
:: STEP 6: Enable IP Forwarding (for ARP Spoof mode)
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 6/7] Configuring IP Forwarding...
echo ──────────────────────────────────────────────

echo [INFO] IP Forwarding is needed for full network monitoring (ARP spoof mode).
echo        This allows your machine to forward traffic from other devices.
echo.

:: Check current status
for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter 2^>nul ^| findstr IPEnableRouter') do set IP_FWD=%%a

if "%IP_FWD%"=="0x1" (
    echo [OK] IP Forwarding is already enabled!
) else (
    echo [INFO] IP Forwarding is currently DISABLED.
    set /p ENABLE_FWD="Enable IP Forwarding? (Y/N): "
    if /i "%ENABLE_FWD%"=="Y" (
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 1 /f >nul 2>&1
        if %errorlevel% equ 0 (
            echo [OK] IP Forwarding enabled! A restart may be required.
        ) else (
            echo [ERROR] Failed to enable. Run this script as Administrator!
        )
    ) else (
        echo [INFO] Skipped. Note: Without IP forwarding, use DEVICE_ONLY_MODE = True
    )
)
echo.

:: ───────────────────────────────────────────────
:: STEP 7: Verify Model Files
:: ───────────────────────────────────────────────
echo ──────────────────────────────────────────────
echo [STEP 7/7] Verifying model files...
echo ──────────────────────────────────────────────

set ALL_OK=1

if exist "models\network_model.pkl" (
    echo [OK] network_model.pkl  — Found
) else (
    echo [MISSING] network_model.pkl  — NOT FOUND!
    set ALL_OK=0
)

if exist "models\scaler.pkl" (
    echo [OK] scaler.pkl         — Found
) else (
    echo [MISSING] scaler.pkl         — NOT FOUND!
    set ALL_OK=0
)

if exist "models\features.pkl" (
    echo [OK] features.pkl       — Found
) else (
    echo [MISSING] features.pkl       — NOT FOUND!
    set ALL_OK=0
)

if exist "scripts\live_ids_auto.py" (
    echo [OK] live_ids_auto.py   — Found
) else (
    echo [MISSING] live_ids_auto.py   — NOT FOUND!
    set ALL_OK=0
)

if exist "scripts\flow_state.py" (
    echo [OK] flow_state.py      — Found
) else (
    echo [MISSING] flow_state.py      — NOT FOUND!
    set ALL_OK=0
)
echo.

:: ───────────────────────────────────────────────
:: FINAL SUMMARY
:: ───────────────────────────────────────────────
echo ══════════════════════════════════════════════
echo                 SETUP COMPLETE!
echo ══════════════════════════════════════════════
echo.

if "%ALL_OK%"=="1" (
    echo   ✓ All dependencies installed
    echo   ✓ All model files present
    echo   ✓ System is ready to run!
    echo.
    echo ┌─────────────────────────────────────────────┐
    echo │  TO START THE IDS:                           │
    echo │                                              │
    echo │  cd scripts                                  │
    echo │  python live_ids_auto.py                     │
    echo │                                              │
    echo │  (Run as Administrator for full features)    │
    echo └─────────────────────────────────────────────┘
) else (
    echo   [WARNING] Some model files are missing!
    echo   Download them from the repository or train the model:
    echo     cd scripts
    echo     python train_network_model.py
)

echo.
echo ──────────────────────────────────────────────
echo Quick Reference:
echo   • Start IDS:       cd scripts ^& python live_ids_auto.py
echo   • Train Model:     cd scripts ^& python train_network_model.py
echo   • Evaluate Model:  cd scripts ^& python evaluate_model.py
echo ──────────────────────────────────────────────
echo.
pause
