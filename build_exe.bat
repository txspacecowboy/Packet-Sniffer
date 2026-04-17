@echo off
title PyShark - Build Standalone EXE
color 0B
echo.
echo  =========================================
echo    PyShark - Build Standalone Executable
echo  =========================================
echo.

:: Install PyInstaller if needed
echo  [*] Checking PyInstaller...
python -m pip install pyinstaller --quiet
echo  [+] PyInstaller ready.
echo.

:: Build the exe
echo  [*] Building PyShark.exe (this may take a minute)...
python -m PyInstaller pyshark.spec --clean --noconfirm

if %errorLevel% NEQ 0 (
    echo.
    echo  [!] Build failed. Check the output above for errors.
    pause
    exit /b 1
)

echo.
echo  =========================================
echo    Build complete!
echo    Executable: dist\PyShark.exe
echo.
echo    Share the dist\PyShark.exe file.
echo    Users must still install Npcap from
echo    https://npcap.com to capture packets.
echo  =========================================
echo.
pause
