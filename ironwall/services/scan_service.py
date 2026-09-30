from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path

from ironwall.core.models import EventType, ScanResult, ScanStatus, SecurityEvent
from ironwall.detection.scanner import ScanningEngine
from ironwall.storage.database import Database


class ScanService:
    def __init__(
        self,
        engine: ScanningEngine,
        database: Database,
        scan_temporary_files: bool = True,
    ) -> None:
        self.engine, self.database, self.scan_temporary_files, self.stop_requested = (
            engine,
            database,
            scan_temporary_files,
            threading.Event(),
        )

    def scan_paths(
        self,
        paths: Iterable[Path],
        on_result: Callable[[ScanResult], None] | None = None,
    ) -> dict:
        self.stop_requested.clear()
        started = time.monotonic()
        totals = {
            "files_scanned": 0,
            "detections": 0,
            "suspicious": 0,
            "errors": 0,
            "stopped": False,
        }
        now = datetime.now(timezone.utc).isoformat()
        session_id = self.database.start_scan_session(now)
        self.database.add_event(
            SecurityEvent(
                EventType.SCAN_STARTED, "Info", "scan", "On-demand scan started"
            )
        )
        for root in paths:
            root = Path(root)
            walk_errors: list[OSError] = []
            if root.is_file() or not root.exists():
                candidates = iter((root,))
            else:
                candidates = (
                    Path(directory) / name
                    for directory, _, names in os.walk(root, onerror=walk_errors.append)
                    for name in names
                )
            for path in candidates:
                if self.stop_requested.is_set():
                    totals["stopped"] = True
                    break
                result = self.engine.scan_file(path)
                totals["files_scanned"] += 1
                if result.status == ScanStatus.DETECTED:
                    totals["detections"] += 1
                elif result.status == ScanStatus.SUSPICIOUS:
                    totals["suspicious"] += 1
                elif result.status == ScanStatus.ERROR:
                    totals["errors"] += 1
                self.database.add_event(
                    SecurityEvent(
                        EventType.FILE_SCANNED,
                        result.severity,
                        "scan",
                        f"Scanned {result.file_name}: {result.status.value}",
                        result.path,
                        "; ".join(result.reasons),
                    )
                )
                if result.status in {ScanStatus.DETECTED, ScanStatus.SUSPICIOUS}:
                    self.database.add_detection(result, "scan")
                if result.status == ScanStatus.DETECTED:
                    self.database.add_event(
                        SecurityEvent(
                            EventType.THREAT_DETECTED,
                            result.severity,
                            "scan",
                            f"Threat detected: {result.threat_name}",
                            result.path,
                            "; ".join(result.reasons),
                        )
                    )
                if on_result:
                    on_result(result)
            for error in walk_errors:
                totals["errors"] += 1
                result = ScanResult(
                    path=str(error.filename or root),
                    status=ScanStatus.ERROR,
                    severity="Error",
                    reasons=[str(error)],
                )
                self.database.add_event(
                    SecurityEvent(
                        EventType.ERROR,
                        "Error",
                        "scan",
                        "Could not access part of the scan path",
                        result.path,
                        str(error),
                    )
                )
                if on_result:
                    on_result(result)
            if self.stop_requested.is_set():
                break
        totals["elapsed_seconds"] = round(time.monotonic() - started, 2)
        self.database.complete_scan_session(
            session_id, datetime.now(timezone.utc).isoformat(), totals
        )
        summary = "Scan stopped by user" if totals["stopped"] else "Scan completed"
        self.database.add_event(
            SecurityEvent(
                EventType.SCAN_COMPLETED,
                "Info",
                "scan",
                f"{summary}: {totals['files_scanned']} files",
            )
        )
        return totals

    def stop(self) -> None:
        self.stop_requested.set()

    def quick_scan_paths(self) -> list[Path]:
        home = Path.home()
        candidates = [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            Path(__import__("tempfile").gettempdir()),
        ]
        if not self.scan_temporary_files:
            candidates.pop()
        return [p for p in candidates if p.exists()]
