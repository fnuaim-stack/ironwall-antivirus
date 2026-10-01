import hashlib
from pathlib import Path

import pytest

from ironwall.core.config import ConfigManager, Settings
from ironwall.core.models import ScanResult, ScanStatus
from ironwall.detection.hash_scanner import EICAR_SHA256
from ironwall.detection.heuristic_scanner import HeuristicScanner
from ironwall.detection.scanner import ScanningEngine
from ironwall.quarantine.manager import QuarantineManager
from ironwall.services.scan_service import ScanService
from ironwall.storage.database import Database

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_is_detected(tmp_path):
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    result = ScanningEngine().scan_file(sample)
    assert (
        result.status is ScanStatus.DETECTED and result.threat_name == "EICAR-Test-File"
    )


def test_eicar_hash_constant_matches_test_file():
    assert hashlib.sha256(EICAR).hexdigest() == EICAR_SHA256


def test_double_extension_is_flagged_by_full_scan(tmp_path):
    sample = tmp_path / "invoice.pdf.exe"
    sample.write_bytes(b"not a portable executable")
    result = ScanningEngine().scan_file(sample)
    assert result.status in {ScanStatus.SUSPICIOUS, ScanStatus.DETECTED}
    assert any("double extension" in reason for reason in result.reasons)


def test_double_extension_heuristic_is_suspicious():
    score, reasons = HeuristicScanner().scan(
        Path("C:/Users/Test/Documents/invoice.pdf.exe")
    )
    assert 30 <= score < 60
    assert any("double extension" in reason for reason in reasons)


def test_quarantine_and_restore(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("safe")
    database = Database(tmp_path / "database.sqlite")
    manager = QuarantineManager(database, tmp_path / "quarantine")
    entry = manager.quarantine(
        ScanResult(
            path=str(source),
            status=ScanStatus.DETECTED,
            file_size=4,
            threat_name="Test",
            reasons=["test"],
        )
    )
    assert not source.exists() and Path(entry["quarantine_path"]).exists()
    assert (
        manager.restore(entry["id"]) == source.resolve()
        and source.read_text() == "safe"
    )


def test_quarantine_rolls_back_if_database_write_fails(tmp_path, monkeypatch):
    source = tmp_path / "sample.txt"
    source.write_text("safe")
    database = Database(tmp_path / "database.sqlite")
    manager = QuarantineManager(database, tmp_path / "quarantine")

    def fail_write(_entry):
        raise RuntimeError("database write failed")

    monkeypatch.setattr(database, "add_quarantine", fail_write)
    with pytest.raises(RuntimeError, match="database write failed"):
        manager.quarantine(
            ScanResult(
                path=str(source),
                status=ScanStatus.DETECTED,
                file_size=4,
                threat_name="Test",
                reasons=["test"],
            )
        )

    assert source.exists()
    assert not any((tmp_path / "quarantine").iterdir())


def test_config_round_trip(tmp_path):
    manager = ConfigManager(tmp_path / "settings.json")
    manager.save(Settings(maximum_file_size_mb=42, monitored_directories=["C:/Test"]))
    assert manager.load().maximum_file_size_mb == 42


def test_scan_service_persists_session_detection_and_events(tmp_path):
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    database = Database(tmp_path / "database.sqlite")
    totals = ScanService(ScanningEngine(), database).scan_paths([sample])
    assert totals["detections"] == 1
    assert database.last_scan()["files_scanned"] == 1
    assert database.dashboard_counts()["detections"] == 1
    assert any(event["event_type"] == "THREAT_DETECTED" for event in database.events())
