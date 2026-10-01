from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ironwall.core.config import Settings
from ironwall.storage.database import Database


class DashboardPage(QWidget):
    def __init__(
        self, database: Database, settings: Settings, quick_scan: Callable[[], None]
    ) -> None:
        super().__init__()
        self.database = database
        self.settings = settings

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h1>IronWall Antivirus</h1>"))
        self.summary = QLabel()
        layout.addWidget(self.summary)

        quick_button = QPushButton("Quick Scan")
        quick_button.clicked.connect(quick_scan)
        layout.addWidget(quick_button)

        layout.addWidget(QLabel("<h3>Recent security events</h3>"))
        self.events = QTableWidget(0, 3)
        self.events.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        layout.addWidget(self.events)

        refresh_button = QPushButton("Refresh dashboard")
        refresh_button.clicked.connect(self.refresh)
        layout.addWidget(refresh_button)
        self.refresh()

    def refresh(self) -> None:
        counts = self.database.dashboard_counts()
        last_scan = self.database.last_scan()
        last_label = last_scan["completed_at"] if last_scan else "Never"
        self.summary.setText(
            f"Protection status: {'Enabled' if self.settings.realtime_enabled else 'Disabled'}\n"
            f"Last scan: {last_label}\n"
            f"Threats detected: {counts['detections']}\n"
            f"Files quarantined: {counts['quarantined']}"
        )

        events = self.database.events(limit=8)
        self.events.setRowCount(len(events))
        for row, event in enumerate(events):
            for column, key in enumerate(("timestamp", "severity", "message")):
                self.events.setItem(
                    row, column, QTableWidgetItem(str(event.get(key) or ""))
                )
