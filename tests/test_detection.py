import json
import os
from pathlib import Path

import pytest

from ironwall.core.models import ScanStatus
from ironwall.detection.hash_scanner import (
    EICAR_MARKER,
    HashScanner,
    contains_eicar,
    sha256_file,
)
from ironwall.detection.scanner import ScanningEngine
from ironwall.detection.yara_scanner import YaraScanner
from ironwall.utils.paths import rules_dir

WANNACRY_SHA256 = {
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
}


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
    assert result.status in {ScanStatus.SUSPICIOUS, ScanStatus.DETECTED}
    assert result.metadata["heuristic_score"] >= 30
    assert any("double extension" in reason for reason in result.reasons)


def test_published_wannacry_hashes_are_in_local_database() -> None:
    data = json.loads((rules_dir() / "hashes.json").read_text(encoding="utf-8"))
    entries = {entry["hash"]: entry for entry in data["hashes"]}
    assert WANNACRY_SHA256 <= entries.keys()
    assert all(entries[digest]["severity"] == "Critical" for digest in WANNACRY_SHA256)
    assert all("source" in entries[digest] for digest in WANNACRY_SHA256)


def test_wannacry_yara_rule_matches_only_combined_safe_indicators(
    tmp_path: Path,
) -> None:
    pytest.importorskip("yara")
    scanner = YaraScanner(rules_dir() / "yara")
    sample = tmp_path / "harmless-wannacry-fixture.bin"
    sample.write_bytes(
        b"MZ\x00safe-test-only\x00@WanaDecryptor@.exe\x00.WNCRY\x00"
        b"Ooops, your files have been encrypted!\x00"
    )
    weak_sample = tmp_path / "single-indicator.bin"
    weak_sample.write_bytes(b"MZ\x00.WNCRY\x00")

    matches = scanner.scan(sample)
    assert scanner.available
    assert any(match["rule"] == "IronWall_Ransomware_WannaCry" for match in matches)
    assert scanner.scan(weak_sample) == []


def test_engine_uses_yara_threat_metadata(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"harmless")
    engine = ScanningEngine()
    monkeypatch.setattr(
        engine.yara,
        "scan",
        lambda _path: [
            {
                "rule": "Test_Rule",
                "tags": [],
                "meta": {
                    "threat_name": "Ransom.Win32.Test",
                    "severity": "Critical",
                },
                "strings": ["$one", "$two"],
            }
        ],
    )

    result = engine.scan_file(sample)
    assert result.status is ScanStatus.DETECTED
    assert result.threat_name == "Ransom.Win32.Test"
    assert result.severity == "Critical"
    assert "$one" in result.reasons[0]
