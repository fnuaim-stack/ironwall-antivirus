import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from shiboken6 import delete

from ironwall.ui.main_window import MainWindow


def test_main_window_constructs_all_pages(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    app.processEvents()
    assert window.windowTitle() == "IronWall Antivirus"
    assert window.pages.count() == 6
    window.close()
    app.processEvents()
    delete(window)
    delete(app)
