# Инструкция по обновлению проекта из GitHub

## После принятия Pull Request в GitHub

### Вариант 1: Через терминал в VSCode (Рекомендуется)

1. **Откройте терминал в VSCode**
   - Нажмите `Ctrl + ~` (тильда/ёмкость)
   - Или меню: View → Terminal

2. **Проверьте текущую ветку**
   ```bash
   git branch
   ```
   Убедитесь, что вы находитесь в той же ветке, в которую был сделан PR (обычно `main` или `master`)

3. **Получите последние изменения**
   ```bash
   git pull origin main
   ```
   Или если вы в другой ветке:
   ```bash
   git pull origin <имя-вашей-ветки>
   ```

4. **Если есть локальные изменения**
   
   **Вариант A: Сохранить изменения (commit)**
   ```bash
   git add .
   git commit -m "Сохранение локальных изменений"
   git pull origin main
   ```
   
   **Вариант B: Временно отложить изменения (stash)**
   ```bash
   git stash
   git pull origin main
   git stash pop
   ```

### Вариант 2: Через интерфейс VSCode

1. **Откройте Source Control**
   - Нажмите `Ctrl + Shift + G`
   - Или иконка с веткой на левой панели

2. **Нажмите на три точки (⋯)** в верхней панели Source Control

3. **Выберите "Pull"** или "Pull (Rebase)"

4. **Если есть конфликты**
   - VSCode покажет файлы с конфликтами
   - Откройте каждый файл
   - Выберите какие изменения оставить (Current Change или Incoming Change)
   - Нажмите "Accept Current" или "Accept Incoming"
   - После разрешения всех конфликтов сделайте commit

### Вариант 3: Через GitHub Desktop (если установлен)

1. Откройте GitHub Desktop
2. Выберите ваш репозиторий
3. Нажмите "Fetch origin"
4. Нажмите "Pull"

## Проверка успешного обновления

После обновления проверьте, что файлы обновились:

```bash
git log --oneline -5
```

Вы должны увидеть последний коммит из вашего PR.

## Если что-то пошло не так

### Конфликты слияния
```bash
# Посмотреть статус
git status

# Отменить слияние
git merge --abort

# Попробовать снова с rebase
git pull --rebase origin main
```

### Случайно удалили изменения
```bash
# Посмотреть историю
git reflog

# Вернуться к коммиту до проблем
git reset --hard HEAD@{1}
```

### Полная переустановка
```bash
# Удалить локальную копию
cd ..
rm -rf BOS_QWEN

# Скачать заново
git clone <URL-вашего-репозитория>
cd BOS_QWEN
pip install -r requirements.txt
```

## Автоматическое обновление (опционально)

Можно настроить автоматическую проверку обновлений:

```bash
# Добавить в .git/config
[branch "main"]
    remote = origin
    merge = refs/heads/main
    rebase = true
```

Тогда команда `git pull` будет использовать rebase автоматически.

## После обновления зависимостей

Если в `requirements.txt` добавились новые пакеты:

```bash
pip install -r requirements.txt --upgrade
```

## Проверка работы после обновления

1. Запустите сервер:
   ```powershell
   python server/gui.py
   ```

2. Запустите клиент:
   ```powershell
   python client/gui.py
   ```

3. Убедитесь, что все функции работают корректно
