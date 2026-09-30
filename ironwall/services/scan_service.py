from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from ironwall.core.models import EventType, ScanResult, ScanStatus, SecurityEvent
from ironwall.detection.scanner import ScanningEngine
from ironwall.storage.database import Database


class ScanService:
    def __init__(self, engine: ScanningEngine, database: Database, scan_temporary_files: bool = True) -> None:
        self.engine, self.database, self.scan_temporary_files, self.stop_requested = engine, database, scan_temporary_files, threading.Event()

    def scan_paths(self, paths: Iterable[Path], on_result: Callable[[ScanResult], None] | None = None) -> dict:
        self.stop_requested.clear(); started = time.monotonic(); totals = {"files_scanned": 0, "detections": 0, "suspicious": 0, "errors": 0}
        now = datetime.now(timezone.utc).isoformat()
        session_id = self.database.start_scan_session(now)
        self.database.add_event(SecurityEvent(EventType.SCAN_STARTED, "Info", "scan", "On-demand scan started"))
        for root in paths:
            candidates = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file())
            for path in candidates:
                if self.stop_requested.is_set(): break
                result = self.engine.scan_file(path); totals["files_scanned"] += 1
                if result.status == ScanStatus.DETECTED: totals["detections"] += 1
                elif result.status == ScanStatus.SUSPICIOUS: totals["suspicious"] += 1
                elif result.status == ScanStatus.ERROR: totals["errors"] += 1
                self.database.add_event(SecurityEvent(EventType.FILE_SCANNED, result.severity, "scan", f"Scanned {result.file_name}: {result.status.value}", result.path, "; ".join(result.reasons)))
                if result.status in {ScanStatus.DETECTED, ScanStatus.SUSPICIOUS}:
                    self.database.add_detection(result, "scan")
                if result.status == ScanStatus.DETECTED: self.database.add_event(SecurityEvent(EventType.THREAT_DETECTED, result.severity, "scan", f"Threat detected: {result.threat_name}", result.path, "; ".join(result.reasons)))
                if on_result: on_result(result)
            if self.stop_requested.is_set(): break
        totals["elapsed_seconds"] = round(time.monotonic()-started, 2)
        self.database.complete_scan_session(session_id, datetime.now(timezone.utc).isoformat(), totals)
        self.database.add_event(SecurityEvent(EventType.SCAN_COMPLETED, "Info", "scan", f"Scan completed: {totals['files_scanned']} files"))
        return totals

    def stop(self) -> None: self.stop_requested.set()

    def quick_scan_paths(self) -> list[Path]:
        home = Path.home(); candidates = [home / "Downloads", home / "Desktop", home / "Documents", Path(__import__("tempfile").gettempdir())]
        if not self.scan_temporary_files: candidates.pop()
        return [p for p in candidates if p.exists()]
