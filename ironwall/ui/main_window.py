from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QListWidget,
    QMainWindow,
    QStackedWidget,
    QWidget,
)

from ironwall.core.config import ConfigManager
from ironwall.detection.scanner import ScanningEngine
from ironwall.quarantine.manager import QuarantineManager
from ironwall.services.scan_service import ScanService
from ironwall.storage.database import Database
from ironwall.ui.dashboard import DashboardPage
from ironwall.ui.events_page import EventsPage
from ironwall.ui.protection_page import ProtectionPage
from ironwall.ui.quarantine_page import QuarantinePage
from ironwall.ui.scanner_page import ScanPage
from ironwall.ui.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("IronWall Antivirus")
        self.resize(1100, 700)

        self.config = ConfigManager()
        self.settings = self.config.load()
        self.database = Database()
        self.engine = ScanningEngine(
            self.settings.maximum_file_size_mb,
            self.settings.heuristics_enabled,
            self.settings.yara_enabled,
        )
        self.quarantine = QuarantineManager(
            self.database, Path(self.settings.quarantine_location)
        )
        self.scan_service = ScanService(
            self.engine,
            self.database,
            self.settings.scan_temporary_files,
        )

        self.pages = QStackedWidget()
        self.scan_page = ScanPage(self.scan_service, self.quarantine)
        self.protection_page = ProtectionPage(
            self.engine,
            self.database,
            self.settings,
            self.quarantine,
            self._save_config,
        )
        self.dashboard_page = DashboardPage(
            self.database, self.settings, self._quick_scan
        )
        self.quarantine_page = QuarantinePage(self.quarantine, self.database)
        self.events_page = EventsPage(self.database)
        self.settings_page = SettingsPage(
            self.settings,
            self.apply_settings,
            self.engine.yara.available,
        )

        page_entries = (
            ("Dashboard", self.dashboard_page),
            ("Scan", self.scan_page),
            ("Real-Time Protection", self.protection_page),
            ("Quarantine", self.quarantine_page),
            ("Security Events", self.events_page),
            ("Settings", self.settings_page),
        )
        self.sidebar = QListWidget()
        self.sidebar.addItems([name for name, _ in page_entries])
        for _, page in page_entries:
            self.pages.addWidget(page)
        self.sidebar.currentRowChanged.connect(self._show_page)
        self.sidebar.setCurrentRow(0)

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.addWidget(self.sidebar, 1)
        layout.addWidget(self.pages, 5)
        self.setCentralWidget(root)

        if self.settings.realtime_enabled:
            self.protection_page.start()

    def _save_config(self) -> None:
        self.config.save(self.settings)

    def _quick_scan(self) -> None:
        self.pages.setCurrentWidget(self.scan_page)
        self.sidebar.setCurrentRow(self.pages.indexOf(self.scan_page))
        self.scan_page.quick()

    def _show_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        page = self.pages.widget(index)
        if page is self.dashboard_page:
            self.dashboard_page.refresh()
        elif page is self.quarantine_page:
            self.quarantine_page.refresh()
        elif page is self.events_page:
            self.events_page.refresh()
        elif page is self.settings_page:
            self.settings_page.refresh_from_settings()

    def apply_settings(
        self,
        *,
        realtime_enabled: bool,
        scan_temporary_files: bool,
        heuristics_enabled: bool,
        yara_enabled: bool,
        maximum_file_size_mb: int,
        quarantine_location: str,
    ) -> None:
        new_location = Path(quarantine_location)
        self.quarantine.change_location(new_location)

        self.settings.scan_temporary_files = scan_temporary_files
        self.settings.heuristics_enabled = heuristics_enabled
        self.settings.yara_enabled = yara_enabled
        self.settings.maximum_file_size_mb = maximum_file_size_mb
        self.settings.quarantine_location = str(self.quarantine.location)
        self.engine.maximum_bytes = maximum_file_size_mb * 1024 * 1024
        self.engine.heuristics_enabled = heuristics_enabled
        self.engine.yara_enabled = yara_enabled
        self.engine.clear_cache()
        self.scan_service.scan_temporary_files = scan_temporary_files

        if realtime_enabled and not self.settings.realtime_enabled:
            self.protection_page.start()
        elif not realtime_enabled and self.settings.realtime_enabled:
            self.protection_page.stop()
        else:
            self.settings.realtime_enabled = realtime_enabled
            self._save_config()

    def closeEvent(self, event) -> None:
        self.scan_service.stop()
        self.protection_page.shutdown()
        event.accept()


def run() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()


def smoke_test() -> int:
    """Construct every page without touching the user's persistent data."""
    import os

    previous_data_directory = os.environ.get("IRONWALL_DATA_DIR")
    try:
        with TemporaryDirectory(prefix="ironwall-smoke-") as data_directory:
            os.environ["IRONWALL_DATA_DIR"] = data_directory
            app = QApplication.instance() or QApplication([])
            window = MainWindow()
            app.processEvents()
            if window.pages.count() != 6:
                return 1
            window.close()
            app.processEvents()
    finally:
        if previous_data_directory is None:
            os.environ.pop("IRONWALL_DATA_DIR", None)
        else:
            os.environ["IRONWALL_DATA_DIR"] = previous_data_directory
    return 0
