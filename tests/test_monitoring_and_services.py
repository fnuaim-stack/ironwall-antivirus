from pathlib import Path

from ironwall.core.models import ScanResult, ScanStatus
from ironwall.monitoring.file_monitor import FileMonitor
from ironwall.services.scan_service import ScanService
from ironwall.storage.database import Database


class DetectedEngine:
    def scan_file(self, path: str) -> ScanResult:
        return ScanResult(
            path=path,
            status=ScanStatus.DETECTED,
            threat_name="Monitor-Test",
            severity="High",
            reasons=["Harmless monitoring test"],
        )


def test_file_monitor_records_detection(tmp_path: Path) -> None:
    database = Database(tmp_path / "database.sqlite")
    detections = []
    monitor = FileMonitor(DetectedEngine(), database, detections.append)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    monitor._scan(str(sample))

    assert detections[0].threat_name == "Monitor-Test"
    assert database.dashboard_counts()["detections"] == 1
    assert database.events("REALTIME_DETECTION")[0]["subject"] == str(sample)


def test_file_monitor_reports_inaccessible_folder(tmp_path: Path) -> None:
    database = Database(tmp_path / "database.sqlite")
    monitor = FileMonitor(DetectedEngine(), database)
    errors = monitor.start([str(tmp_path / "missing")])
    assert errors
    monitor.stop()


def test_scan_service_records_missing_path_as_error(tmp_path: Path) -> None:
    database = Database(tmp_path / "database.sqlite")
    from ironwall.detection.scanner import ScanningEngine

    totals = ScanService(ScanningEngine(), database).scan_paths([tmp_path / "missing"])
    assert totals["files_scanned"] == 1
    assert totals["errors"] == 1
    assert database.last_scan()["errors"] == 1


def test_file_monitor_defers_scan_until_file_stops_changing(tmp_path: Path) -> None:
    database = Database(tmp_path / "database.sqlite")
    monitor = FileMonitor(DetectedEngine(), database, settle_seconds=0.05)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"first")
    monitor.schedule(str(sample), False)
    sample.write_bytes(b"second version")

    try:
        import time

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if database.dashboard_counts()["detections"]:
                break
            time.sleep(0.02)
        assert database.dashboard_counts()["detections"] == 1
    finally:
        monitor.stop()
