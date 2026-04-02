@echo off
REM Build script for BOS Server GUI executable (Windows)

echo 🔨 Building BOS Server Executable...

REM Clean previous builds
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

REM Build with PyInstaller
pyinstaller --name="BOS_Server" ^
    --windowed ^
    --onefile ^
    --hidden-import customtkinter ^
    --hidden-import jinja2 ^
    server\gui.py

echo.
echo ✅ Server executable created: dist\BOS_Server.exe
echo.
pause
