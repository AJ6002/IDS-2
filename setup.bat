@echo off
echo ==========================================================
echo Network Intrusion Detection System - Setup Script
echo ==========================================================

echo.
echo [1/3] Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b
)

echo.
echo [2/3] Installing Python dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [3/3] System Requirement Reminder:
echo IMPORTANT: This project requires Wireshark/TShark to be installed.
echo If you haven't installed it yet, download it from: https://www.wireshark.org/download.html
echo Ensure 'TShark' is selected during installation and added to PATH.

echo.
echo Setup Complete! 
echo To run the project:
echo 1. Run 'python wireshark-CONVERTOR.py' to process raw PCAP data.
echo 2. Run 'python wireshaark_IDS.py' to run the detection model.
echo.
pause
