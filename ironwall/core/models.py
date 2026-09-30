from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class ScanStatus(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    DETECTED = "DETECTED"
    ERROR = "ERROR"


class EventType(str, Enum):
    FILE_SCANNED = "FILE_SCANNED"
    THREAT_DETECTED = "THREAT_DETECTED"
    FILE_QUARANTINED = "FILE_QUARANTINED"
    FILE_RESTORED = "FILE_RESTORED"
    REALTIME_DETECTION = "REALTIME_DETECTION"
    PROCESS_STARTED = "PROCESS_STARTED"
    PROCESS_DETECTION = "PROCESS_DETECTION"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    ERROR = "ERROR"


@dataclass(slots=True)
class ScanResult:
    path: str
    status: ScanStatus
    file_name: str = ""
    file_size: int = 0
    sha256: str | None = None
    file_type: str = "unknown"
    threat_name: str | None = None
    severity: str = "Info"
    reasons: list[str] = field(default_factory=list)
    scanners: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0

    def __post_init__(self) -> None:
        if not self.file_name:
            self.file_name = Path(self.path).name

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


@dataclass(slots=True)
class SecurityEvent:
    event_type: EventType
    severity: str
    source: str
    message: str
    subject: str | None = None
    details: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
