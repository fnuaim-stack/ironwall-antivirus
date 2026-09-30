from __future__ import annotations

import threading
import time
from ironwall.core.models import EventType, ScanStatus, SecurityEvent


class ProcessMonitor:
    def __init__(self, engine, database, interval: float = 3.0) -> None:
        self.engine, self.database, self.interval = engine, database, interval; self._stop = threading.Event(); self._thread = None; self._known = set()
    def start(self) -> None:
        if self._thread and self._thread.is_alive(): return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True); self._thread.start()
    def _run(self) -> None:
        try: import psutil
        except ImportError: return
        while not self._stop.is_set():
            for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "username", "create_time"]):
                if proc.pid in self._known: continue
                self._known.add(proc.pid); info = proc.info; exe = info.get("exe")
                self.database.add_event(SecurityEvent(EventType.PROCESS_STARTED, "Info", "process", f"Process started: {info.get('name')}", exe, str(info)))
                if exe:
                    result = self.engine.scan_file(exe)
                    if result.status == ScanStatus.DETECTED: self.database.add_event(SecurityEvent(EventType.PROCESS_DETECTION, result.severity, "process", f"Detected process executable: {result.threat_name}", exe, "; ".join(result.reasons)))
            self._stop.wait(self.interval)
    def stop(self) -> None: self._stop.set()
