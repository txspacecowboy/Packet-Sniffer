@echo off
title PyShark Installer
color 0A
echo.
echo  =========================================
echo    PyShark - Network Protocol Analyzer
echo    Installer
echo  =========================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo  [!] This installer requires Administrator privileges.
    echo  [!] Please right-click install.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Check Python is installed
python --version >nul 2>&1
if %errorLevel% NEQ 0 (
    echo  [!] Python is not installed or not on PATH.
    echo  [!] Download Python from https://python.org and re-run this installer.
    echo.
    pause
    exit /b 1
)

echo  [+] Python found.
echo.

:: Install Scapy
echo  [*] Installing required packages...
python -m pip install scapy --quiet
if %errorLevel% NEQ 0 (
    echo  [!] Failed to install Scapy. Check your internet connection.
    pause
    exit /b 1
)
echo  [+] Scapy installed.
echo.

:: Check for Npcap
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if %errorLevel% NEQ 0 (
    echo  [!] Npcap is not installed. PyShark needs Npcap to capture packets.
    echo  [!] Download it from: https://npcap.com
    echo.
    echo  After installing Npcap, re-run this installer or create the shortcut manually.
    echo.
    pause
)

:: Create desktop shortcut
echo  [*] Creating desktop shortcut...
set SCRIPT_DIR=%~dp0
set PYTHON_EXE=
for /f "delims=" %%i in ('where pythonw 2^>nul') do set PYTHON_EXE=%%i

if "%PYTHON_EXE%"=="" (
    for /f "delims=" %%i in ('where python') do set PYTHON_EXE=%%i
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ws = New-Object -ComObject WScript.Shell; ^
   $desktop = [System.Environment]::GetFolderPath('Desktop'); ^
   $sc = $ws.CreateShortcut($desktop + '\PyShark.lnk'); ^
   $sc.TargetPath = '%PYTHON_EXE%'; ^
   $sc.Arguments = '\"'+ '%SCRIPT_DIR%src\network_analyzer.py' +'\"'; ^
   $sc.WorkingDirectory = '%SCRIPT_DIR%'; ^
   $sc.Description = 'PyShark Network Protocol Analyzer'; ^
   $sc.IconLocation = 'C:\Windows\System32\netsh.exe,0'; ^
   $sc.Save()"

if %errorLevel% NEQ 0 (
    echo  [!] Could not create desktop shortcut.
) else (
    echo  [+] Desktop shortcut created.
)

echo.
echo  =========================================
echo    Installation complete!
echo.
echo    Launch PyShark from your desktop.
echo    Always run as Administrator to capture
echo    network packets.
echo  =========================================
echo.
pause
