@echo off
setlocal enabledelayedexpansion

title IoT Sentinel Pro — Campus Edition
echo ===============================================================================
echo            IoT Sentinel Pro — Campus Edition (Windows 11 Launcher)
echo           Defensive IoT Security Auditor ^& Vulnerability Engine
echo                           100%% Free ^& Zero-Cost
echo ===============================================================================
echo.

:: 1. Detect Python
echo [*] Checking Python installation...
set "PY_CMD="

python --version >nul 2>&1
if !errorlevel! equ 0 (
    set "PY_CMD=python"
) else (
    py --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY_CMD=py"
    )
)

if "!PY_CMD!"=="" (
    echo [!] ERROR: Python 3 was not detected on this system.
    echo.
    echo Please install Python 3.10+ (Free ^& Open Source):
    echo 1. Download installer from: https://www.python.org/downloads/
    echo 2. IMPORTANT: Check the box "Add python.exe to PATH" during installation.
    echo 3. Re-run this launcher script after installation completes.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('!PY_CMD! --version 2^>^&1') do echo [✓] Detected: %%i

:: 2. Check Nmap (Optional for Demo Mode, required for Live Scanning)
echo [*] Checking Nmap installation...
where nmap >nul 2>&1
if !errorlevel! equ 0 (
    for /f "tokens=*" %%i in ('nmap --version 2^>^&1') do (
        echo [✓] Nmap detected: %%i
        goto :nmap_done
    )
) else (
    echo [i] Notice: Nmap was not detected in system PATH.
    echo     - The application will run seamlessly in 100%% Offline Demo Mode.
    echo     - To enable Live Network Scanning on authorized private subnets,
    echo       download free Nmap from: https://nmap.org/download.html
)
:nmap_done

:: 3. Setup Virtual Environment
if not exist ".venv" (
    echo [*] Creating Python virtual environment in .venv...
    !PY_CMD! -m venv .venv
    if !errorlevel! neq 0 (
        echo [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [✓] Virtual environment created.
)

:: 4. Activate Virtual Environment
echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat
if !errorlevel! neq 0 (
    echo [!] Failed to activate virtual environment.
    pause
    exit /b 1
)
echo [✓] Virtual environment active (.venv).

:: 5. Install Dependencies
echo [*] Verifying and installing required packages from requirements.txt...
pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if !errorlevel! neq 0 (
    echo [!] Warning: Dependency installation reported errors. Attempting to continue...
) else (
    echo [✓] All dependencies verified.
)

:: 6. Ensure runtime directories exist
if not exist "data" mkdir data
if not exist "reports" mkdir reports

:: 7. Launch Streamlit Cyber Dashboard
echo.
echo ===============================================================================
echo [*] Launching IoT Sentinel Pro — Campus Edition Dashboard...
echo [*] Opening in default web browser at http://localhost:8501
echo [*] Press Ctrl+C in this terminal window to stop the server.
echo ===============================================================================
echo.

streamlit run app.py

pause
