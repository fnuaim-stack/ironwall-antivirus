from __future__ import annotations

import time
from pathlib import Path

from ironwall.core.models import ScanResult, ScanStatus
from .hash_scanner import HashScanner, sha256_file
from .heuristic_scanner import HeuristicScanner
from .pe_scanner import PEScanner
from .yara_scanner import YaraScanner


class ScanningEngine:
    def __init__(self, maximum_size_mb: int = 100, heuristics_enabled: bool = True, yara_enabled: bool = True) -> None:
        self.maximum_bytes = maximum_size_mb * 1024 * 1024
        self.heuristics_enabled, self.yara_enabled = heuristics_enabled, yara_enabled
        self.hash_scanner, self.heuristic, self.pe, self.yara = HashScanner(), HeuristicScanner(), PEScanner(), YaraScanner()

    def scan_file(self, file_path: str | Path) -> ScanResult:
        started, path = time.perf_counter(), Path(file_path)
        try:
            stat = path.stat()
            if not path.is_file(): raise ValueError("Path is not a regular file")
            if stat.st_size > self.maximum_bytes:
                return self._result(path, ScanStatus.CLEAN, stat.st_size, reasons=["Skipped: file exceeds configured size limit"], duration=started)
            digest = sha256_file(path)
            hash_match = self.hash_scanner.scan(path, digest)
            if hash_match:
                return self._result(path, ScanStatus.DETECTED, stat.st_size, digest, hash_match["threat_name"], hash_match.get("severity", "High"), [hash_match.get("description", "Matched local threat hash")], ["hash"], started)
            score, reasons, scanners = 0, [], []
            if self.heuristics_enabled:
                points, notes = self.heuristic.scan(path); score += points; reasons += notes
                if notes: scanners.append("heuristic")
            pe_score, pe_notes, _ = self.pe.scan(path); score += pe_score; reasons += pe_notes
            if pe_notes: scanners.append("pe")
            if self.yara_enabled:
                matches = self.yara.scan(path)
                if matches:
                    return self._result(path, ScanStatus.DETECTED, stat.st_size, digest, matches[0]["rule"], "High", [f"YARA rule matched: {m['rule']}" for m in matches], ["yara"], started)
            status = ScanStatus.DETECTED if score >= 60 else ScanStatus.SUSPICIOUS if score >= 30 else ScanStatus.CLEAN
            return self._result(path, status, stat.st_size, digest, "Heuristic.HighRisk" if status == ScanStatus.DETECTED else None, "High" if status == ScanStatus.DETECTED else "Medium" if status == ScanStatus.SUSPICIOUS else "Info", reasons, scanners, started)
        except Exception as exc:
            return ScanResult(path=str(path), status=ScanStatus.ERROR, reasons=[str(exc)], severity="Error", duration_ms=(time.perf_counter()-started)*1000)

    @staticmethod
    def _result(path, status, size, digest=None, threat=None, severity="Info", reasons=None, scanners=None, duration=0.0):
        return ScanResult(path=str(path), status=status, file_size=size, sha256=digest, threat_name=threat, severity=severity, reasons=reasons or [], scanners=scanners or [], file_type=path.suffix.lower() or "unknown", duration_ms=(time.perf_counter()-duration)*1000)
