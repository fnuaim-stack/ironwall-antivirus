from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ironwall.core.models import EventType, ScanResult, SecurityEvent
from ironwall.detection.hash_scanner import sha256_file
from ironwall.storage.database import Database


class QuarantineManager:
    def __init__(self, database: Database, location: Path) -> None:
        self.database, self.location = database, location.resolve()
        self.location.mkdir(parents=True, exist_ok=True)

    def change_location(self, location: Path) -> None:
        """Move managed entries when the user changes the quarantine folder."""
        new_location = location.resolve()
        if new_location == self.location:
            return
        new_location.mkdir(parents=True, exist_ok=True)
        for entry in self.database.quarantine_entries():
            source = Path(entry["quarantine_path"]).resolve()
            if source.parent != self.location:
                raise ValueError("A quarantine entry is outside the managed location")
            destination = (new_location / entry["id"]).resolve()
            if source.exists():
                shutil.move(str(source), str(destination))
            self.database.update_quarantine_path(entry["id"], str(destination))
        self.location = new_location

    def quarantine(self, result: ScanResult) -> dict:
        source = Path(result.path).resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        if Path(result.path).is_symlink():
            raise ValueError("Symbolic links cannot be quarantined")
        entry_id = uuid.uuid4().hex
        destination = (self.location / entry_id).resolve()
        if destination.parent != self.location:
            raise ValueError("Invalid quarantine path")
        digest = result.sha256 or sha256_file(source)
        shutil.move(str(source), str(destination))
        entry = {
            "id": entry_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "original_path": str(source),
            "quarantine_path": str(destination),
            "threat_name": result.threat_name or "Suspicious file",
            "sha256": digest,
            "file_size": result.file_size,
            "reason": "; ".join(result.reasons),
        }
        try:
            self.database.add_quarantine(entry)
        except Exception:
            if destination.exists() and not source.exists():
                shutil.move(str(destination), str(source))
            raise
        self.database.add_event(
            SecurityEvent(
                EventType.FILE_QUARANTINED,
                "High",
                "quarantine",
                f"Quarantined {source.name}",
                str(source),
                entry["reason"],
            )
        )
        return entry

    def restore(self, entry_id: str, destination: Path | None = None) -> Path:
        entry = self.database.quarantine_entry(entry_id)
        if not entry:
            raise KeyError("Quarantine entry not found")
        source = Path(entry["quarantine_path"]).resolve()
        if source.parent != self.location or not source.is_file():
            raise ValueError("Invalid or missing quarantine file")
        if sha256_file(source) != entry["sha256"]:
            raise ValueError("Quarantined file failed integrity verification")
        target = (destination or Path(entry["original_path"])).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(target)
        shutil.move(str(source), str(target))
        self.database.remove_quarantine(entry_id)
        self.database.add_event(
            SecurityEvent(
                EventType.FILE_RESTORED,
                "Info",
                "quarantine",
                f"Restored {target.name}",
                str(target),
            )
        )
        return target

    def delete(self, entry_id: str) -> None:
        entry = self.database.quarantine_entry(entry_id)
        if not entry:
            raise KeyError("Quarantine entry not found")
        source = Path(entry["quarantine_path"]).resolve()
        if source.parent != self.location:
            raise ValueError("Invalid quarantine path")
        if source.exists():
            source.unlink()
        self.database.remove_quarantine(entry_id)
        self.database.add_event(
            SecurityEvent(
                EventType.FILE_DELETED,
                "Info",
                "quarantine",
                f"Permanently deleted quarantined file {entry_id}",
                entry["original_path"],
            )
        )
