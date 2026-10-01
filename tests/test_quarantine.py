from pathlib import Path

import pytest

from ironwall.core.models import ScanResult, ScanStatus
from ironwall.detection.hash_scanner import sha256_file
from ironwall.quarantine.manager import QuarantineManager
from ironwall.storage.database import Database


def detected_result(path: Path) -> ScanResult:
    return ScanResult(
        path=str(path),
        status=ScanStatus.DETECTED,
        file_size=path.stat().st_size,
        sha256=sha256_file(path),
        threat_name="Harmless-Test",
        reasons=["Unit test"],
    )


def test_quarantine_location_change_preserves_restore(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"test")
    database = Database(tmp_path / "database.sqlite")
    manager = QuarantineManager(database, tmp_path / "old-quarantine")
    entry = manager.quarantine(detected_result(source))

    manager.change_location(tmp_path / "new-quarantine")
    moved_entry = database.quarantine_entry(entry["id"])
    assert (
        Path(moved_entry["quarantine_path"]).parent
        == (tmp_path / "new-quarantine").resolve()
    )
    assert manager.restore(entry["id"]) == source.resolve()


def test_restore_rejects_tampered_quarantine_file(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"original")
    database = Database(tmp_path / "database.sqlite")
    manager = QuarantineManager(database, tmp_path / "quarantine")
    entry = manager.quarantine(detected_result(source))
    Path(entry["quarantine_path"]).write_bytes(b"tampered")

    with pytest.raises(ValueError, match="integrity"):
        manager.restore(entry["id"])


def test_delete_removes_entry_and_records_event(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"test")
    database = Database(tmp_path / "database.sqlite")
    manager = QuarantineManager(database, tmp_path / "quarantine")
    entry = manager.quarantine(detected_result(source))

    manager.delete(entry["id"])
    assert database.quarantine_entry(entry["id"]) is None
    assert database.events("FILE_DELETED")[0]["event_type"] == "FILE_DELETED"


def test_quarantine_rejects_symbolic_link(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"test")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("Symbolic links are unavailable")
    database = Database(tmp_path / "database.sqlite")
    manager = QuarantineManager(database, tmp_path / "quarantine")

    with pytest.raises(ValueError, match="Symbolic"):
        manager.quarantine(detected_result(link))
