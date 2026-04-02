#!/bin/bash

echo "=========================================="
echo "BOS Client - Запуск на PyQt6"
echo "=========================================="
echo ""

# Проверка наличия виртуального окружения
if [ ! -d "venv" ]; then
    echo "Создание виртуального окружения..."
    python3 -m venv venv
fi

# Активация виртуального окружения
source venv/bin/activate

# Установка зависимостей
echo "Установка зависимостей..."
pip install -r requirements.txt --quiet

# Запуск приложения
echo ""
echo "Запуск BOS Client на PyQt6..."
echo ""
python client/gui_pyqt6.py
