from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ironwall.core.models import ScanResult, ScanStatus

from .clamav_scanner import ClamAVScanner
from .hash_scanner import HashScanner, sha256_file
from .heuristic_scanner import HeuristicScanner
from .pe_scanner import PEScanner
from .yara_scanner import YaraScanner


class ScanningEngine:
    def __init__(
        self,
        maximum_size_mb: int = 100,
        heuristics_enabled: bool = True,
        yara_enabled: bool = True,
        cache_size: int = 512,
    ) -> None:
        self.maximum_bytes = maximum_size_mb * 1024 * 1024
        self.heuristics_enabled, self.yara_enabled = heuristics_enabled, yara_enabled
        self.hash_scanner, self.heuristic, self.pe, self.yara = (
            HashScanner(),
            HeuristicScanner(),
            PEScanner(),
            YaraScanner(),
        )
        self.clamav = ClamAVScanner()
        self.cache_size = max(0, cache_size)
        self._cache: OrderedDict[tuple, ScanResult] = OrderedDict()
        self._cache_lock = threading.RLock()

    def scan_file(self, file_path: str | Path) -> ScanResult:
        started, path = time.perf_counter(), Path(file_path)
        try:
            stat = path.stat()
            if not path.is_file():
                raise ValueError("Path is not a regular file")
            if stat.st_size > self.maximum_bytes:
                return self._result(
                    path,
                    ScanStatus.ERROR,
                    stat.st_size,
                    severity="Info",
                    reasons=[
                        "File was not scanned because it exceeds the configured size limit"
                    ],
                    duration=started,
                )
            rule_revisions = (
                self.hash_scanner.revision(),
                self.yara.revision() if self.yara_enabled else (),
            )
            cache_key = (
                str(path.resolve()),
                stat.st_size,
                stat.st_mtime_ns,
                stat.st_ctime_ns,
                stat.st_dev,
                stat.st_ino,
                rule_revisions,
            )
            with self._cache_lock:
                # ClamAV signatures can update independently of IronWall files.
                cached = None if self.clamav.available else self._cache.get(cache_key)
                if cached is not None:
                    self._cache.move_to_end(cache_key)
                    return replace(
                        cached,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        duration_ms=(time.perf_counter() - started) * 1000,
                    )
            digest = sha256_file(path)
            hash_match = self.hash_scanner.scan(path, digest)
            if hash_match:
                result = self._result(
                    path,
                    ScanStatus.DETECTED,
                    stat.st_size,
                    digest,
                    hash_match["threat_name"],
                    hash_match.get("severity", "High"),
                    [hash_match.get("description", "Matched local threat hash")],
                    ["hash"],
                    started,
                )
                return self._finish(path, stat, rule_revisions, cache_key, result)
            score, reasons, scanners = 0, [], []
            if self.heuristics_enabled:
                points, notes = self.heuristic.scan(path)
                score += points
                reasons += notes
                if notes:
                    scanners.append("heuristic")
            pe_score, pe_notes, pe_details = self.pe.scan(path)
            score += pe_score
            reasons += pe_notes
            if pe_details and pe_details.get("provider") != "unavailable":
                scanners.append("pe")
            if self.yara_enabled:
                matches = self.yara.scan(path)
                if matches:
                    primary = matches[0]
                    meta = primary.get("meta", {})
                    threat_name = str(meta.get("threat_name") or primary["rule"])
                    severity = str(meta.get("severity") or "High")
                    reasons = []
                    for match in matches:
                        matched_strings = ", ".join(match.get("strings", []))
                        detail = f"YARA rule matched: {match['rule']}"
                        if matched_strings:
                            detail += f" ({matched_strings})"
                        reasons.append(detail)
                    result = self._result(
                        path,
                        ScanStatus.DETECTED,
                        stat.st_size,
                        digest,
                        threat_name,
                        severity,
                        reasons,
                        ["yara"],
                        started,
                        {"yara_matches": matches, "pe": pe_details},
                    )
                    return self._finish(path, stat, rule_revisions, cache_key, result)
            if self.clamav.available:
                signature = self.clamav.scan(path)
                if signature:
                    result = self._result(
                        path,
                        ScanStatus.DETECTED,
                        stat.st_size,
                        digest,
                        signature,
                        "High",
                        [f"ClamAV local signature matched: {signature}"],
                        ["clamav"],
                        started,
                    )
                    return self._finish(path, stat, rule_revisions, cache_key, result)
            status = (
                ScanStatus.DETECTED
                if score >= 60
                else ScanStatus.SUSPICIOUS
                if score >= 30
                else ScanStatus.CLEAN
            )
            provider_errors = self.hash_scanner.errors + (
                self.yara.errors if self.yara_enabled else []
            )
            if provider_errors:
                reasons += [f"Rule provider error: {message}" for message in provider_errors]
                if status == ScanStatus.CLEAN:
                    status = ScanStatus.ERROR
            result = self._result(
                path,
                status,
                stat.st_size,
                digest,
                "Heuristic.HighRisk" if status == ScanStatus.DETECTED else None,
                "High"
                if status == ScanStatus.DETECTED
                else "Medium"
                if status == ScanStatus.SUSPICIOUS
                else "Error"
                if status == ScanStatus.ERROR
                else "Info",
                reasons,
                scanners,
                started,
                {"heuristic_score": score, "pe": pe_details},
            )
            return self._finish(path, stat, rule_revisions, cache_key, result)
        except Exception as exc:  # noqa: BLE001 - scanner boundary must return ERROR
            return ScanResult(
                path=str(path),
                status=ScanStatus.ERROR,
                reasons=[str(exc)],
                severity="Error",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

    def _finish(
        self,
        path: Path,
        initial_stat,
        rule_revisions: tuple,
        key: tuple,
        result: ScanResult,
    ) -> ScanResult:
        try:
            current = path.stat()
            changed = (
                current.st_size != initial_stat.st_size
                or current.st_mtime_ns != initial_stat.st_mtime_ns
                or current.st_ctime_ns != initial_stat.st_ctime_ns
                or current.st_dev != initial_stat.st_dev
                or current.st_ino != initial_stat.st_ino
                or self.hash_scanner.revision() != rule_revisions[0]
                or (self.yara_enabled and self.yara.revision() != rule_revisions[1])
            )
        except OSError:
            changed = True
        if changed:
            return ScanResult(
                path=str(path),
                status=ScanStatus.ERROR,
                severity="Error",
                reasons=["File or detection rules changed during scanning; retry the scan"],
            )
        return self._remember(key, result)

    def _remember(self, key: tuple, result: ScanResult) -> ScanResult:
        with self._cache_lock:
            if self.cache_size and not self.clamav.available:
                self._cache[key] = result
                self._cache.move_to_end(key)
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
        return result

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    @staticmethod
    def _result(
        path,
        status,
        size,
        digest=None,
        threat=None,
        severity="Info",
        reasons=None,
        scanners=None,
        duration=0.0,
        metadata=None,
    ):
        return ScanResult(
            path=str(path),
            status=status,
            file_size=size,
            sha256=digest,
            threat_name=threat,
            severity=severity,
            reasons=reasons or [],
            scanners=scanners or [],
            metadata=metadata or {},
            file_type=path.suffix.lower() or "unknown",
            duration_ms=(time.perf_counter() - duration) * 1000,
        )
