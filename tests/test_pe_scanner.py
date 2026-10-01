from pathlib import Path

from ironwall.detection.pe_scanner import PEScanner


def test_pe_scanner_recognizes_disguised_mz_file(tmp_path: Path) -> None:
    sample = tmp_path / "photo.jpg"
    sample.write_bytes(b"MZ" + b"not-a-real-pe")

    score, reasons, details = PEScanner().scan(sample)

    assert score == 0
    assert details == {}
    assert any("could not parse" in reason for reason in reasons)


def test_pe_scanner_skips_non_pe_content(tmp_path: Path) -> None:
    sample = tmp_path / "document.txt"
    sample.write_text("ordinary text", encoding="utf-8")

    assert PEScanner().scan(sample) == (0, [], {})
