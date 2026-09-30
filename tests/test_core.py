from pathlib import Path

from ironwall.core.config import ConfigManager, Settings
from ironwall.core.models import ScanResult, ScanStatus
from ironwall.detection.scanner import ScanningEngine
from ironwall.quarantine.manager import QuarantineManager
from ironwall.storage.database import Database

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def test_eicar_is_detected(tmp_path):
    sample = tmp_path / "eicar.com"; sample.write_bytes(EICAR)
    result = ScanningEngine().scan_file(sample)
    assert result.status is ScanStatus.DETECTED and result.threat_name == "EICAR-Test-File"

def test_double_extension_is_suspicious(tmp_path):
    sample = tmp_path / "invoice.pdf.exe"; sample.write_bytes(b"not a portable executable")
    result = ScanningEngine().scan_file(sample)
    assert result.status is ScanStatus.SUSPICIOUS and "double extension" in result.reasons[0]

def test_quarantine_and_restore(tmp_path):
    source = tmp_path / "sample.txt"; source.write_text("safe")
    database = Database(tmp_path / "database.sqlite"); manager = QuarantineManager(database, tmp_path / "quarantine")
    entry = manager.quarantine(ScanResult(path=str(source), status=ScanStatus.DETECTED, file_size=4, threat_name="Test", reasons=["test"]))
    assert not source.exists() and Path(entry["quarantine_path"]).exists()
    assert manager.restore(entry["id"]) == source.resolve() and source.read_text() == "safe"

def test_config_round_trip(tmp_path):
    manager = ConfigManager(tmp_path / "settings.json")
    manager.save(Settings(maximum_file_size_mb=42, monitored_directories=["C:/Test"]))
    assert manager.load().maximum_file_size_mb == 42
