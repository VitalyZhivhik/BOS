@echo off
REM Build script for BOS Client GUI executable (Windows)

echo 🔨 Building BOS Client Executable...

REM Clean previous builds
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

REM Build with PyInstaller
pyinstaller --name="BOS_Client" ^
    --windowed ^
    --onefile ^
    --hidden-import customtkinter ^
    --hidden-import scapy ^
    client\gui.py

echo.
echo ✅ Client executable created: dist\BOS_Client.exe
echo.
pause
