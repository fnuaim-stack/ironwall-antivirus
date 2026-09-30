import logging
from logging.handlers import RotatingFileHandler

from .paths import app_data_dir


def configure_logging() -> None:
    logs = app_data_dir() / "Logs"
    logs.mkdir(exist_ok=True)
    handler = RotatingFileHandler(logs / "ironwall.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=[handler])
