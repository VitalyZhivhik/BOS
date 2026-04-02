@echo off
chcp 65001 >nul
echo ==========================================
echo BOS Client - Запуск на PyQt6
echo ==========================================
echo.

REM Проверка наличия виртуального окружения
if not exist "venv" (
    echo Создание виртуального окружения...
    python -m venv venv
)

REM Активация виртуального окружения
call venv\Scripts\activate.bat

REM Установка зависимостей
echo Установка зависимостей...
pip install -r requirements.txt --quiet

REM Запуск приложения
echo.
echo Запуск BOS Client на PyQt6...
echo.
python client\gui_pyqt6.py

pause
