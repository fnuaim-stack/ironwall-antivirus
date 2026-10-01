import subprocess
from pathlib import Path

import pytest

from ironwall.core.models import ScanStatus
from ironwall.detection.clamav_scanner import ClamAVScanner
from ironwall.detection.scanner import ScanningEngine


def test_clamav_verdict_is_reported_by_engine(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"inert test bytes")
    engine = ScanningEngine()
    engine.clamav = ClamAVScanner(executable="clamscan")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, f"{sample}: Test.Signature FOUND\n", ""
        ),
    )

    result = engine.scan_file(sample)
    assert result.status is ScanStatus.DETECTED
    assert result.threat_name == "Test.Signature"
    assert result.scanners == ["clamav"]


def test_clamav_scan_error_is_not_clean(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"inert test bytes")
    engine = ScanningEngine()
    engine.clamav = ClamAVScanner(executable="clamscan")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 2, "", "Database is missing"
        ),
    )

    result = engine.scan_file(sample)
    assert result.status is ScanStatus.ERROR
    assert "Database is missing" in result.reasons[0]


def test_clamav_timeout_is_not_clean(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"inert test bytes")
    scanner = ClamAVScanner(executable="clamscan", timeout=1)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("clamscan", 1)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        scanner.scan(sample)
