"""
Shared utilities and helper functions.
"""

import logging
import json
from typing import Any, Dict, Optional
from pathlib import Path


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Настройка логгирования."""
    logger = logging.getLogger("security_analyzer")
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
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
