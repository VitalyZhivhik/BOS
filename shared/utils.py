"""
Shared utilities and helper functions.
"""

import logging
import json
import sys
from typing import Any, Dict, Optional
from pathlib import Path

try:
    import colorlog
    HAS_COLORLOG = True
except ImportError:
    HAS_COLORLOG = False


def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> logging.Logger:
    """Настройка логгирования с поддержкой цветов и записи в файл."""
    logger = logging.getLogger("security_analyzer")
    logger.setLevel(level)
    
    # Очищаем существующие обработчики
    if logger.handlers:
        logger.handlers.clear()
    
    # Консольный обработчик с цветами (если доступен colorlog)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if HAS_COLORLOG:
        color_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s%(reset)s',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            },
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(color_formatter)
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    # Файловый обработчик (если указан файл)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")
    
    return logger


def load_config(config_path: str) -> Dict[str, Any]:
    """Загрузка конфигурации из JSON файла."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(data: Any, filepath: str, indent: int = 2) -> None:
    """Сохранение данных в JSON файл."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def load_json(filepath: str) -> Any:
    """Загрузка данных из JSON файла."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


logger = setup_logging()
