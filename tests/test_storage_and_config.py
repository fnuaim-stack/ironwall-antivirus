from pathlib import Path

from ironwall.core.config import ConfigManager, Settings
from ironwall.core.models import EventType, SecurityEvent
from ironwall.storage.database import Database


def test_empty_monitored_directory_list_round_trips(tmp_path: Path) -> None:
    manager = ConfigManager(tmp_path / "settings.json")
    manager.save(Settings(monitored_directories=[]))
    assert manager.load().monitored_directories == []


def test_invalid_config_falls_back_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"maximum_file_size_mb": "invalid"}', encoding="utf-8")
    assert ConfigManager(path).load().maximum_file_size_mb == 100


def test_event_filter_accepts_multiple_types(tmp_path: Path) -> None:
    database = Database(tmp_path / "database.sqlite")
    database.add_event(SecurityEvent(EventType.SCAN_STARTED, "Info", "scan", "start"))
    database.add_event(SecurityEvent(EventType.ERROR, "Error", "scan", "error"))
    database.add_event(SecurityEvent(EventType.SCAN_COMPLETED, "Info", "scan", "done"))
    events = database.events(("SCAN_STARTED", "SCAN_COMPLETED"))
    assert {event["event_type"] for event in events} == {
        "SCAN_STARTED",
        "SCAN_COMPLETED",
    }
