#!/usr/bin/env python3
"""
BOS Client - Приложение для сканирования и анализа векторов атак
GUI на PyQt6 с русским интерфейсом и руководством пользователя
"""

import sys
import os
import json
from PyQt6.QtGui import QAction
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QSpinBox, QComboBox, QProgressBar,
    QTextEdit, QTabWidget, QFrame, QGroupBox, QScrollArea, QMessageBox,
    QFileDialog, QSplitter, QSizePolicy, QStatusBar, QMenu, QMenuBar,
    QDialog, QDialogButtonBox, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QIcon, QColor, QPalette, QActionGroup

from shared.models import AttackVector, ScanResult
from client.scanner.port_scanner import PortScanner


class ScanWorker(QThread):
    """Рабочий поток для сканирования портов"""
    progress = pyqtSignal(int, int, int, int)  # scanned, open, filtered, closed
    finished = pyqtSignal(object)  # ScanResult
    error = pyqtSignal(str)
    log_message = pyqtSignal(str)

    def __init__(self, target: str, port_start: int, port_end: int, scan_type: str):
        super().__init__()
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.scan_type = scan_type
        self.scanner = PortScanner()

    def run(self):
        try:
            self.log_message.emit("Запуск сканирования...")
            
            def callback(scanned, open_count, filtered, closed):
                self.progress.emit(scanned, open_count, filtered, closed)
            
            result = self.scanner.scan(
                target=self.target,
                port_start=self.port_start,
                port_end=self.port_end,
                scan_type=self.scan_type,
                callback=callback
            )
            
            self.log_message.emit(f"Сканирование завершено. Найдено {len(result.open_ports)} открытых портов.")
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self.scanner.stop_scan()


class UserManualDialog(QDialog):
    """Диалог руководства пользователя"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Руководство пользователя BOS Client")
        self.setMinimumSize(800, 600)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("📖 Руководство пользователя BOS Client")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Создаем прокручиваемую область
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        # Разделы руководства
        sections = [
            self._create_section(
                "1. О программе",
                """BOS Client - это программа для сканирования сетевых портов и выявления возможных векторов атак.
Программа предназначена для учебных целей и помогает понять принципы работы сетевой безопасности.

Возможности программы:
• Сканирование TCP/UDP портов
• Определение запущенных служб
• Идентификация векторов атак по базе MITRE ATT&CK
• Экспорт результатов в различные форматы
• Интеграция с утилитой ScanOval"""
            ),
            self._create_section(
                "2. Начало работы",
                """Шаг 1: Запустите программу BOS Client
Шаг 2: Введите IP-адрес или имя хоста цели в поле "Целевой IP/Хост"
Шаг 3: Укажите диапазон портов для сканирования (по умолчанию 1-1000)
Шаг 4: Выберите тип сканирования (TCP Connect, SYN Scan, UDP Scan)
Шаг 5: Нажмите кнопку "🚀 Начать сканирование"

Пример: Для сканирования локального сервера введите 192.168.1.1 или localhost"""
            ),
            self._create_section(
                "3. Интерфейс программы",
                """Главное окно состоит из следующих элементов:

📋 Панель конфигурации:
   • Поле ввода целевого IP/хоста
   • Настройка диапазона портов
   • Выбор типа сканирования
   • Кнопки управления (Старт/Стоп/Экспорт/Отправить)

📊 Панель прогресса:
   • Прогресс-бар выполнения сканирования
   • Статистика: просканировано портов, открытые, фильтруемые, закрытые

📑 Вкладки результатов:
   1. "Открытые порты" - список найденных открытых портов
   2. "Векторы атак" - выявленные векторы атак с описанием
   3. "Службы" - обнаруженные сетевые службы
   4. "ScanOval" - интеграция с утилитой сканирования уязвимостей
   5. "Руководство" - быстрая справка

📝 Журнал активности:
   • Отображение хода сканирования в реальном времени
   • Сообщения об ошибках и предупреждения"""
            ),
            self._create_section(
                "4. Работа с результатами",
                """После завершения сканирования вы можете:

💾 Экспортировать результаты:
   1. Нажмите кнопку "💾 Экспорт результатов"
   2. Выберите формат (JSON или TXT)
   3. Укажите имя файла и место сохранения

📤 Отправить на сервер:
   1. Нажмите кнопку "📤 Отправить на сервер"
   2. Сохраните файл с векторами атак
   3. Передайте файл администратору сервера

🔍 Фильтрация портов:
   • Используйте выпадающий список для фильтрации по протоколу (All/TCP/UDP)"""
            ),
            self._create_section(
                "5. Утилита ScanOval",
                """ScanOval - это встроенная утилита для поиска уязвимостей по базе OVAL.

Как использовать:
1. Перейдите на вкладку "ScanOval"
2. Введите CVE-идентификатор (например, CVE-2021-44228)
3. Нажмите "Проверить уязвимость"
4. Получите информацию о уязвимости и способах защиты

База OVAL содержит информацию о:
• Известных уязвимостях (CVE)
• Способах обнаружения уязвимостей
• Рекомендациях по устранению"""
            ),
            self._create_section(
                "6. Типы сканирования",
                """🔹 TCP Connect - полное TCP соединение (наиболее надёжный)
🔹 SYN Scan - половинчатое соединение (скрытное)
🔹 UDP Scan - сканирование UDP портов (медленнее)
🔹 Service Detection - определение версий служб

Рекомендации:
• Для быстрого сканирования используйте TCP Connect
• Для скрытного сканирования выберите SYN Scan
• Для полного анализа включите Service Detection"""
            ),
            self._create_section(
                "7. Меры предосторожности",
                """⚠️ ВАЖНО: Используйте эту программу только в учебных целях!

• Сканируйте только те системы, на которые у вас есть разрешение
• Не используйте программу для незаконной деятельности
• Все действия логируются и могут быть отслежены
• Ответственность за использование программы лежит на пользователе

Для легального тестирования:
• Используйте собственные виртуальные машины
• Работайте в изолированной лабораторной сети
• Получите письменное разрешение перед тестированием чужих систем"""
            ),
            self._create_section(
                "8. Часто задаваемые вопросы",
                """❓ Почему сканирование занимает много времени?
   → Большое количество портов или медленная сеть увеличивают время сканирования

❓ Что значит статус "Filtered"?
   → Порт блокируется фаерволом, ответ не получен

❓ Можно ли сканировать удалённые серверы?
   → Только при наличии разрешения владельца сервера

❓ Где сохраняются результаты?
   → Результаты сохраняются в выбранную вами папку при экспорте

❓ Как обновить базу уязвимостей?
   → Обновление происходит автоматически при подключении к интернету"""
            )
        ]
        
        for section in sections:
            content_layout.addWidget(section)
        
        scroll.setWidget(content_widget)
        layout.addWidget(scroll)
        
        # Кнопка закрытия
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedWidth(150)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignCenter)
    
    def _create_section(self, title: str, content: str) -> QFrame:
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(frame)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #4CAF50;")
        layout.addWidget(title_label)
        
        content_label = QLabel(content)
        content_label.setWordWrap(True)
        content_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(content_label)
        
        return frame


class ScanOvalWidget(QWidget):
    """Виджет утилиты ScanOval"""
    
    def __init__(self):
        super().__init__()
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("🔍 ScanOval - Поиск уязвимостей по базе OVAL")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Описание
        desc = QLabel("Утилита для проверки уязвимостей по идентификаторам CVE и базе OVAL")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # Поле ввода CVE
        input_group = QGroupBox("Поиск уязвимости")
        input_layout = QHBoxLayout(input_group)
        
        input_layout.addWidget(QLabel("CVE ID:"))
        self.cve_input = QLineEdit()
        self.cve_input.setPlaceholderText("Например: CVE-2021-44228")
        input_layout.addWidget(self.cve_input)
        
        self.search_btn = QPushButton("🔍 Проверить уязвимость")
        self.search_btn.clicked.connect(self._search_vulnerability)
        input_layout.addWidget(self.search_btn)
        
        layout.addWidget(input_group)
        
        # Результаты
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText("Здесь появится информация о найденной уязвимости...")
        layout.addWidget(self.result_text)
        
        # Примеры
        examples_group = QGroupBox("Примеры известных уязвимостей")
        examples_layout = QVBoxLayout(examples_group)
        
        examples = [
            "CVE-2021-44228 - Log4Shell (Apache Log4j)",
            "CVE-2017-0144 - EternalBlue (SMB)",
            "CVE-2019-11043 - PHP-FPM Remote Code Execution",
            "CVE-2020-1472 - Zerologon (Netlogon)"
        ]
        
        for example in examples:
            lbl = QLabel(f"• {example}")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            examples_layout.addWidget(lbl)
        
        layout.addWidget(examples_group)
    
    def _search_vulnerability(self):
        cve_id = self.cve_input.text().strip()
        
        if not cve_id:
            QMessageBox.warning(self, "Предупреждение", "Введите CVE-идентификатор")
            return
        
        # Имитация поиска (в реальной версии - запрос к API)
        self.result_text.clear()
        self.result_text.append(f"🔍 Поиск информации о {cve_id}...\n")
        
        # Здесь должна быть логика запроса к базе OVAL
        # Для демонстрации покажем заглушку
        result = f"""
═══════════════════════════════════════════════
Результаты поиска для: {cve_id}
═══════════════════════════════════════════════

Статус: Требуется подключение к базе OVAL

Примечание:
Для полноценной работы ScanOval необходимо:
1. Подключиться к серверу с базой OVAL
2. Или скачать локальную базу уязвимостей

В текущей версии демонстрируется интерфейс утилиты.
Интеграция с реальной базой OVAL требует настройки API.
"""
        self.result_text.append(result)


class ClientGUI(QMainWindow):
    """Основное окно приложения BOS Client"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BOS Client - Сканер векторов атак")
        self.setMinimumSize(1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QLabel {
                color: #ffffff;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
            QPushButton#stopBtn {
                background-color: #f44336;
            }
            QPushButton#stopBtn:hover {
                background-color: #da190b;
            }
            QPushButton#exportBtn {
                background-color: #2196F3;
            }
            QPushButton#exportBtn:hover {
                background-color: #0b7dda;
            }
            QPushButton#sendBtn {
                background-color: #ff9800;
            }
            QPushButton#sendBtn:hover {
                background-color: #e68900;
            }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #555555;
                padding: 6px;
                border-radius: 3px;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
                margin-right: 5px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #555555;
                selection-background-color: #4CAF50;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #2d2d2d;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2d2d2d;
            }
            QTabBar::tab {
                background-color: #3d3d3d;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #4CAF50;
            }
            QTextEdit {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #555555;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                color: #4CAF50;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        
        self.scanner = PortScanner()
        self.scan_worker: Optional[ScanWorker] = None
        self.current_results: Optional[ScanResult] = None
        self.current_attack_vectors: List[AttackVector] = []
        self.all_open_ports: List[Dict] = []
        
        self._create_menu()
        self._create_ui()
        self._create_statusbar()
        
        self._log_message("Программа готова к работе")
    
    def _create_menu(self):
        menubar = self.menuBar()
        
        # Меню Файл
        file_menu = menubar.addMenu("Файл")
        
        export_action = QAction("💾 Экспорт результатов", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self._export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Выход", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Меню Справка
        help_menu = menubar.addMenu("Справка")
        
        manual_action = QAction("📖 Руководство пользователя", self)
        manual_action.setShortcut("F1")
        manual_action.triggered.connect(self._show_manual)
        help_menu.addAction(manual_action)
        
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _create_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Готов")
    
    def _create_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        
        # Заголовок
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)
        
        title_label = QLabel("🎯 BOS Client - Сканер векторов атак")
        title_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #4CAF50;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        self.status_label = QLabel("Статус: Готов")
        self.status_label.setStyleSheet("color: #888888; font-size: 14px;")
        header_layout.addWidget(self.status_label)
        
        main_layout.addWidget(header_frame)
        
        # Панель конфигурации
        config_group = QGroupBox("Конфигурация сканирования")
        config_layout = QVBoxLayout(config_group)
        
        # Целевой IP
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("Целевой IP/Хост:"))
        self.target_ip_input = QLineEdit()
        self.target_ip_input.setPlaceholderText("192.168.1.1")
        self.target_ip_input.setMinimumWidth(250)
        ip_layout.addWidget(self.target_ip_input)
        config_layout.addLayout(ip_layout)
        
        # Диапазон портов
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Диапазон портов:"))
        
        self.port_start_spin = QSpinBox()
        self.port_start_spin.setRange(1, 65535)
        self.port_start_spin.setValue(1)
        port_layout.addWidget(self.port_start_spin)
        
        port_layout.addWidget(QLabel("-"))
        
        self.port_end_spin = QSpinBox()
        self.port_end_spin.setRange(1, 65535)
        self.port_end_spin.setValue(1000)
        port_layout.addWidget(self.port_end_spin)
        config_layout.addLayout(port_layout)
        
        # Тип сканирования
        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Тип сканирования:"))
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "TCP Connect",
            "SYN Scan", 
            "UDP Scan",
            "Service Detection"
        ])
        scan_type_layout.addWidget(self.scan_type_combo)
        config_layout.addLayout(scan_type_layout)
        
        # Кнопки управления
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Начать сканирование")
        self.start_btn.clicked.connect(self._start_scan)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Остановить")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        self.export_btn = QPushButton("💾 Экспорт результатов")
        self.export_btn.setObjectName("exportBtn")
        self.export_btn.clicked.connect(self._export_results)
        self.export_btn.setEnabled(False)
        button_layout.addWidget(self.export_btn)
        
        self.send_btn = QPushButton("📤 Отправить на сервер")
        self.send_btn.setObjectName("sendBtn")
        self.send_btn.clicked.connect(self._send_to_server)
        self.send_btn.setEnabled(False)
        button_layout.addWidget(self.send_btn)
        
        config_layout.addLayout(button_layout)
        main_layout.addWidget(config_group)
        
        # Прогресс
        progress_group = QGroupBox("Прогресс сканирования")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("Прогресс: 0% - Готов")
        progress_layout.addWidget(self.progress_label)
        
        self.stats_label = QLabel("Просканировано: 0 | Открыто: 0 | Фильтруется: 0 | Закрыто: 0")
        self.stats_label.setStyleSheet("color: #888888;")
        progress_layout.addWidget(self.stats_label)
        
        main_layout.addWidget(progress_group)
        
        # Вкладки результатов
        self.tabs = QTabWidget()
        
        # Вкладка открытых портов
        self.open_ports_tab = QWidget()
        self._setup_open_ports_tab()
        self.tabs.addTab(self.open_ports_tab, "Открытые порты")
        
        # Вкладка векторов атак
        self.attack_vectors_tab = QWidget()
        self._setup_attack_vectors_tab()
        self.tabs.addTab(self.attack_vectors_tab, "Векторы атак")
        
        # Вкладка служб
        self.services_tab = QWidget()
        self._setup_services_tab()
        self.tabs.addTab(self.services_tab, "Службы")
        
        # Вкладка ScanOval
        self.scanoval_widget = ScanOvalWidget()
        self.tabs.addTab(self.scanoval_widget, "ScanOval")
        
        # Вкладка руководства
        self.manual_tab = QWidget()
        self._setup_manual_tab()
        self.tabs.addTab(self.manual_tab, "Руководство")
        
        main_layout.addWidget(self.tabs, stretch=1)
        
        # Журнал
        log_group = QGroupBox("Журнал активности")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(100)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        main_layout.addWidget(log_group)
    
    def _setup_open_ports_tab(self):
        layout = QVBoxLayout(self.open_ports_tab)
        
        # Фильтр
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Фильтр по протоколу:"))
        
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["Все", "TCP", "UDP"])
        self.protocol_filter.currentTextChanged.connect(self._filter_ports)
        filter_layout.addWidget(self.protocol_filter)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Список портов
        self.ports_text = QTextEdit()
        self.ports_text.setReadOnly(True)
        self.ports_text.setPlaceholderText("Здесь отобразятся открытые порты после сканирования...")
        layout.addWidget(self.ports_text)
    
    def _setup_attack_vectors_tab(self):
        layout = QVBoxLayout(self.attack_vectors_tab)
        
        self.attack_text = QTextEdit()
        self.attack_text.setReadOnly(True)
        self.attack_text.setPlaceholderText("Здесь отобразятся выявленные векторы атак...")
        layout.addWidget(self.attack_text)
    
    def _setup_services_tab(self):
        layout = QVBoxLayout(self.services_tab)
        
        self.services_text = QTextEdit()
        self.services_text.setReadOnly(True)
        self.services_text.setPlaceholderText("Здесь отобразятся обнаруженные службы...")
        layout.addWidget(self.services_text)
    
    def _setup_manual_tab(self):
        layout = QVBoxLayout(self.manual_tab)
        
        title = QLabel("📖 Быстрое руководство")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #4CAF50;")
        layout.addWidget(title)
        
        quick_guide = QLabel("""
1. Введите IP-адрес цели в поле "Целевой IP/Хост"
2. Настройте диапазон портов (по умолчанию 1-1000)
3. Выберите тип сканирования
4. Нажмите "🚀 Начать сканирование"
5. Дождитесь завершения и изучите результаты

Для подробной справки нажмите F1 или меню "Справка → Руководство пользователя"
""")
        quick_guide.setWordWrap(True)
        layout.addWidget(quick_guide)
        
        layout.addStretch()
    
    def _log_message(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )
    
    def _update_progress(self, scanned: int, open_count: int, filtered: int, closed: int):
        total = self.port_end_spin.value() - self.port_start_spin.value() + 1
        percent = int((scanned / total) * 100) if total > 0 else 0
        
        self.progress_bar.setValue(percent)
        self.progress_label.setText(f"Прогресс: {percent}%")
        self.stats_label.setText(
            f"Просканировано: {scanned} | Открыто: {open_count} | "
            f"Фильтруется: {filtered} | Закрыто: {closed}"
        )
        self.statusbar.showMessage(f"Сканирование: {scanned}/{total}")
    
    def _validate_target(self, target: str) -> tuple:
        if not target.strip():
            return False, "Введите IP-адрес или имя хоста"
        
        import ipaddress
        try:
            ipaddress.ip_address(target.strip())
            return True, ""
        except ValueError:
            if '.' in target and len(target) > 3:
                return True, ""
            return False, "Неверный формат IP-адреса или хоста"
    
    def _start_scan(self):
        target = self.target_ip_input.text().strip()
        valid, error = self._validate_target(target)
        
        if not valid:
            QMessageBox.critical(self, "Ошибка валидации", error)
            return
        
        port_start = self.port_start_spin.value()
        port_end = self.port_end_spin.value()
        
        if port_start > port_end:
            QMessageBox.critical(self, "Ошибка", "Начальный порт должен быть меньше конечного")
            return
        
        scan_type = self.scan_type_combo.currentText().lower()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.send_btn.setEnabled(False)
        
        self._log_message(f"Запуск сканирования {target}:{port_start}-{port_end}")
        self._log_message(f"Тип сканирования: {self.scan_type_combo.currentText()}")
        
        self.scan_worker = ScanWorker(target, port_start, port_end, scan_type)
        self.scan_worker.progress.connect(self._update_progress)
        self.scan_worker.finished.connect(self._scan_finished)
        self.scan_worker.error.connect(self._scan_error)
        self.scan_worker.log_message.connect(self._log_message)
        self.scan_worker.start()
        
        self.statusbar.showMessage("Сканирование запущено...")
    
    def _stop_scan(self):
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Остановить текущее сканирование?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes and self.scan_worker:
            self.scan_worker.stop()
            self._log_message("Сканирование остановлено пользователем")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.statusbar.showMessage("Сканирование остановлено")
    
    def _scan_finished(self, result: ScanResult):
        self.current_results = result
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.send_btn.setEnabled(True)
        
        self._display_open_ports(result.open_ports)
        self._generate_attack_vectors(result)
        self._display_services(result.identified_services)
        
        self._log_message(f"Сканирование завершено. Найдено {len(result.open_ports)} открытых портов.")
        self.statusbar.showMessage("Сканирование завершено")
    
    def _scan_error(self, error: str):
        QMessageBox.critical(self, "Ошибка сканирования", f"Сканирование не удалось: {error}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._log_message(f"Ошибка: {error}")
        self.statusbar.showMessage("Ошибка сканирования")
    
    def _display_open_ports(self, open_ports: List[Dict]):
        self.all_open_ports = open_ports
        self._filter_ports("Все")
    
    def _filter_ports(self, protocol: str):
        self.ports_text.clear()
        
        if not self.all_open_ports:
            self.ports_text.append("Открытые порты не найдены.")
            return
        
        if protocol == "Все":
            filtered = self.all_open_ports
        else:
            filtered = [p for p in self.all_open_ports if p.get('protocol', '').upper() == protocol.upper()]
        
        if not filtered:
            self.ports_text.append(f"Порты {protocol} не найдены.")
            return
        
        header = f"""
╔══════════════════════════════════════════════════╗
         ОТКРЫТЫЕ ПОРТЫ ({len(filtered)} найдено)
╚══════════════════════════════════════════════════╝

ПОРТ       ПРОТОКОЛ  СОСТОЯНИЕ  СЛУЖБА
───────────────────────────────────────────────────
"""
        self.ports_text.append(header)
        
        for port in filtered:
            line = f"{port['port']:<10} {port.get('protocol', 'N/A'):<9} {port.get('state', 'unknown'):<10} {port.get('service', 'unknown')}"
            self.ports_text.append(line)
    
    def _generate_attack_vectors(self, scan_result: ScanResult):
        self.attack_text.clear()
        
        if not scan_result.open_ports:
            self.attack_text.append("Векторы атак не выявлены - открытых портов не найдено.")
            return
        
        attack_vectors = self.scanner.identify_attack_vectors(scan_result)
        self.current_attack_vectors = attack_vectors
        
        header = f"""
╔══════════════════════════════════════════════════╗
      ВЫЯВЛЕННЫЕ ВЕКТОРЫ АТАК ({len(attack_vectors)})
╚══════════════════════════════════════════════════╝
"""
        self.attack_text.append(header)
        
        for av in attack_vectors:
            info = f"""
🎯 {av.name}
   Порт: {av.port}/{av.protocol}
   MITRE ATT&CK: {av.mitre_technique or 'N/A'}
   CAPEC: {av.capec_id or 'N/A'}
   Описание: {av.description}
   
───────────────────────────────────────────────────
"""
            self.attack_text.append(info)
    
    def _display_services(self, services: List[Dict]):
        self.services_text.clear()
        
        if not services:
            self.services_text.append("Службы не обнаружены.")
            return
        
        header = f"""
╔══════════════════════════════════════════════════╗
         ОБНАРУЖЕННЫЕ СЛУЖБЫ ({len(services)})
╚══════════════════════════════════════════════════╝

СЛУЖБА              ПОРТ    ПРОТОКОЛ  ВЕРСИЯ
───────────────────────────────────────────────────
"""
        self.services_text.append(header)
        
        for service in services:
            version = service.get('version', 'unknown') or 'unknown'
            line = f"{service.get('name', 'unknown'):<20} {service['port']:<7} {service.get('protocol', 'N/A'):<9} {version}"
            self.services_text.append(line)
    
    def _export_results(self):
        if not self.current_results:
            QMessageBox.warning(self, "Предупреждение", "Нет результатов для экспорта. Выполните сканирование.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт результатов",
            f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "JSON файлы (*.json);;Текстовые файлы (*.txt);;Все файлы (*)"
        )
        
        if filename:
            try:
                ext = os.path.splitext(filename)[1].lower()
                
                if ext == ".json":
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.current_results.to_dict(), f, indent=2, ensure_ascii=False)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(str(self.current_results))
                
                self._log_message(f"Результаты экспортированы: {filename}")
                QMessageBox.information(self, "Успех", f"Результаты сохранены:\n{filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать результаты: {e}")
    
    def _send_to_server(self):
        """Отправка результатов сканирования на сервер через API."""
        if not self.current_results or not self.current_results.open_ports:
            QMessageBox.warning(self, "Предупреждение", "Нет результатов сканирования для отправки.")
            return
        
        # URL сервера (можно вынести в настройки)
        server_url = "http://localhost:8000/api/scan-results"
        
        self._log_message(f"Отправка результатов на сервер: {server_url}")
        
        try:
            import requests
            
            # Подготовка данных для отправки
            data = {
                "timestamp": datetime.now().isoformat(),
                "target_ip": self.current_results.target_ip,
                "open_ports": self.current_results.open_ports,
                "attack_vectors": [av.to_dict() for av in self.current_results.attack_vectors]
            }
            
            # Отправка POST запроса на сервер
            response = requests.post(server_url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                self._log_message(f"Результаты успешно отправлены на сервер. {result.get('message', '')}")
                QMessageBox.information(
                    self, "Успех",
                    f"Результаты сканирования отправлены на сервер!\n\n"
                    f"Портов отправлено: {result.get('ports_received', 0)}\n"
                    f"Векторов атак: {result.get('vectors_received', 0)}\n\n"
                    f"Сервер начал обработку уязвимостей через ScanOval."
                )
            else:
                raise Exception(f"Сервер вернул ошибку: {response.status_code} - {response.text}")
                
        except ImportError:
            # Если requests не установлен, сохраняем в файл
            self._log_message("Модуль requests не найден, сохраняем в файл")
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить результаты для сервера",
                f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "JSON файлы (*.json)"
            )
            
            if filename:
                data = {
                    "timestamp": datetime.now().isoformat(),
                    "target_ip": self.current_results.target_ip,
                    "open_ports": self.current_results.open_ports,
                    "attack_vectors": [av.to_dict() for av in self.current_results.attack_vectors]
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                self._log_message(f"Результаты сохранены в файл: {filename}")
                QMessageBox.information(
                    self, "Успех",
                    f"Результаты сохранены в файл:\n{filename}\n\n"
                    f"Передайте этот файл администратору сервера или установите модуль requests\n"
                    f"для автоматической отправки (pip install requests)"
                )
        except requests.exceptions.ConnectionError:
            self._log_message("Ошибка подключения к серверу. Проверьте, запущен ли сервер.")
            QMessageBox.critical(
                self, "Ошибка подключения",
                "Не удалось подключиться к серверу.\n\n"
                "Убедитесь, что сервер запущен командой:\n"
                "python server/api_server.py\n\n"
                "Или сохраните результаты в файл для ручной передачи."
            )
        except Exception as e:
            self._log_message(f"Ошибка при отправке на сервер: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось отправить данные на сервер:\n{e}")
    
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = ClientGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
