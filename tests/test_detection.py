import json
import os
from pathlib import Path

from ironwall.core.models import ScanStatus
from ironwall.detection.hash_scanner import (
    EICAR_MARKER,
    HashScanner,
    contains_eicar,
    sha256_file,
)
from ironwall.detection.scanner import ScanningEngine


def test_eicar_can_span_streaming_chunks(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 13 + EICAR_MARKER + b"B" * 10)
    assert contains_eicar(sample, chunk_size=16)


def test_hash_database_refreshes_without_restart(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"known harmless test content")
    rules = tmp_path / "hashes.json"
    rules.write_text('{"hashes": []}', encoding="utf-8")
    scanner = HashScanner(rules)
    assert scanner.scan(sample) is None

    rules.write_text(
        json.dumps(
            {
                "hashes": [
                    {
                        "hash": sha256_file(sample),
                        "threat_name": "Local-Test-Hash",
                        "severity": "Test",
                        "description": "Harmless unit-test rule",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    stat = rules.stat()
    os.utime(rules, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    assert scanner.scan(sample)["threat_name"] == "Local-Test-Hash"


def test_oversized_file_is_not_reported_clean(tmp_path: Path) -> None:
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"x" * 32)
    result = ScanningEngine(maximum_size_mb=0).scan_file(sample)
    assert result.status is ScanStatus.ERROR
    assert "exceeds" in result.reasons[0]


def test_scan_cache_invalidates_when_file_changes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("first", encoding="utf-8")
    engine = ScanningEngine()
    first = engine.scan_file(sample)
    sample.write_text("second and different", encoding="utf-8")
    second = engine.scan_file(sample)
    assert first.sha256 != second.sha256


def test_scan_result_contains_explainable_score(tmp_path: Path) -> None:
    sample = tmp_path / "invoice.pdf.exe"
    sample.write_bytes(b"not a PE file")
    result = ScanningEngine().scan_file(sample)
    assert result.status is ScanStatus.SUSPICIOUS
    assert result.metadata["heuristic_score"] >= 30
    assert any("double extension" in reason for reason in result.reasons)
