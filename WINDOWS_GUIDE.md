# 🪟 Руководство по запуску BOS в Windows

## ✅ Исправленные ошибки

Были исправлены следующие проблемы:
1. **ImportError: cannot import name 'ServerInfo'** - заменено на `ServerInfrastructure`
2. **ImportError: cannot import name 'AttackVectorIdentifier'** - удалено из импорта

## 📋 Требования

- Python 3.8 или выше
- Windows 10/11
- PowerShell или Command Prompt

## 🚀 Установка и запуск

### 1. Откройте PowerShell в папке проекта

```powershell
cd C:\BOS_QWEN\BOS
```

### 2. Создайте виртуальное окружение (рекомендуется)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> ⚠️ Если ошибка выполнения скриптов, выполните:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### 3. Установите зависимости

```powershell
pip install -r requirements.txt
```

### 4. Запустите серверную часть (GUI)

```powershell
python server\gui.py
```

### 5. Запустите клиентскую часть (GUI) в новом окне PowerShell

```powershell
python client\gui.py
```

## 📦 Создание EXE файлов

### Для сервера:

```powershell
.\build_server.bat
```

После сборки EXE файл будет в папке `dist/BOS_Server/`

### Для клиента:

```powershell
.\build_client.bat
```

После сборки EXE файл будет в папке `dist/BOS_Client/`

## ⚠️ Важные замечания

1. **НЕ используйте синтаксис Linux** в Windows:
   - ❌ `PYTHONPATH=/workspace python server/main.py`
   - ✅ `python server\gui.py`

2. **IP адрес для сканирования**:
   - Введите IP адрес в поле ввода GUI
   - Не используйте `<IP>` - это только пример в документации

3. **Брандмауэр Windows**:
   - При первом запуске может появиться запрос брандмауэра
   - Разрешите доступ для работы сети

## 🎮 Использование GUI

### Серверная часть:
1. Нажмите **"Анализировать сервер"** для сбора информации
2. Просмотрите уязвимости во вкладке **"Vulnerabilities"**
3. Проверьте векторы атак во вкладке **"Attack Vectors"**
4. Получите рекомендации во вкладке **"Recommendations"**
5. Экспортируйте отчёт в JSON/HTML/TXT

### Клиентская часть:
1. Введите IP адрес целевого сервера
2. Выберите диапазон портов (по умолчанию 1-1000)
3. Нажмите **"Начать сканирование"**
4. Просмотрите открытые порты и службы
5. Экспортируйте результаты в JSON

## 🔧 Решение проблем

### Ошибка: "No module named 'customtkinter'"
```powershell
pip install customtkinter pyinstaller pillow
```

### Ошибка: " tkinter not found"
Установите Python с опцией tcl/tk или переустановите Python с https://python.org

### Ошибка выполнения скриптов PowerShell
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📞 Поддержка

При возникновении проблем:
1. Проверьте версию Python: `python --version`
2. Проверьте установленные пакеты: `pip list`
3. Пересоздайте виртуальное окружение
