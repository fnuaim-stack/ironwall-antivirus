from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from ironwall.utils.paths import app_data_dir


@dataclass
class Settings:
    realtime_enabled: bool = False
    monitored_directories: list[str] | None = None
    scan_temporary_files: bool = True
    maximum_file_size_mb: int = 100
    heuristics_enabled: bool = True
    yara_enabled: bool = True
    quarantine_location: str = ""

    def __post_init__(self) -> None:
        self.maximum_file_size_mb = max(1, min(int(self.maximum_file_size_mb), 4096))
        if self.monitored_directories is None:
            home = Path.home()
            self.monitored_directories = [
                str(p) for p in (home / "Downloads", home / "Desktop") if p.exists()
            ]
        else:
            self.monitored_directories = list(
                dict.fromkeys(
                    str(Path(item)) for item in self.monitored_directories if item
                )
            )
        if not self.quarantine_location:
            self.quarantine_location = str(app_data_dir() / "Quarantine")


class ConfigManager:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or app_data_dir() / "settings.json"

    def load(self) -> Settings:
        try:
            return Settings(**json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return Settings()

    def save(self, settings: Settings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
        temporary.replace(self.path)
