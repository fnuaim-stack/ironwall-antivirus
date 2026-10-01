from __future__ import annotations

import threading
from pathlib import Path

from ironwall.core.models import EventType, ScanStatus, SecurityEvent


class FileMonitor:
    """watchdog-backed monitor with a per-path settle debounce."""

    def __init__(
        self, engine, database, on_detection=None, settle_seconds: float = 1.0
    ) -> None:
        self.engine, self.database, self.on_detection, self.settle_seconds = (
            engine,
            database,
            on_detection,
            settle_seconds,
        )
        self.observer = None
        self.pending: dict[str, threading.Timer] = {}
        self._pending_lock = threading.Lock()

    def start(self, directories: list[str]) -> list[str]:
        if self.observer is not None:
            return []
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            return ["watchdog is not installed"]
        monitor = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                monitor.schedule(event.src_path, event.is_directory)

            def on_modified(self, event):
                monitor.schedule(event.src_path, event.is_directory)

            def on_moved(self, event):
                monitor.schedule(event.dest_path, event.is_directory)

        observer = Observer()
        errors = []
        scheduled = 0
        for directory in directories:
            if not Path(directory).is_dir():
                errors.append(f"{directory}: folder is unavailable")
                continue
            try:
                observer.schedule(Handler(), directory, recursive=True)
                scheduled += 1
            except OSError as exc:
                errors.append(f"{directory}: {exc}")
        if scheduled:
            try:
                observer.start()
                self.observer = observer
            except OSError as exc:
                errors.append(f"Could not start file monitoring: {exc}")
                observer.unschedule_all()
        elif not directories:
            errors.append("No monitored folders are configured")
        return errors

    def schedule(self, value: str, is_directory: bool) -> None:
        if is_directory:
            return
        with self._pending_lock:
            old = self.pending.pop(value, None)
            if old:
                old.cancel()
            timer = threading.Timer(self.settle_seconds, self._scan, args=(value,))
            self.pending[value] = timer
            timer.start()

    def _scan(self, value: str) -> None:
        with self._pending_lock:
            self.pending.pop(value, None)
        result = self.engine.scan_file(value)
        if result.status == ScanStatus.DETECTED:
            self.database.add_detection(result, "realtime")
            self.database.add_event(
                SecurityEvent(
                    EventType.REALTIME_DETECTION,
                    result.severity,
                    "realtime",
                    f"Threat detected: {result.threat_name}",
                    result.path,
                    "; ".join(result.reasons),
                )
            )
            if self.on_detection:
                self.on_detection(result)

    def stop(self) -> None:
        with self._pending_lock:
            for timer in self.pending.values():
                timer.cancel()
            self.pending.clear()
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            self.observer = None
