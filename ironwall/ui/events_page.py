from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ironwall.storage.database import Database

EVENT_FILTERS = {
    "All": None,
    "Detection": ("THREAT_DETECTED", "PROCESS_DETECTION"),
    "Scanning": ("SCAN_STARTED", "SCAN_COMPLETED", "FILE_SCANNED"),
    "Monitoring": ("REALTIME_DETECTION",),
    "Process": ("PROCESS_STARTED", "PROCESS_DETECTION"),
    "Quarantine": ("FILE_QUARANTINED", "FILE_RESTORED", "FILE_DELETED"),
    "Errors": ("ERROR",),
}


class EventsPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        layout = QVBoxLayout(self)
        self.filter = QComboBox()
        self.filter.addItems(EVENT_FILTERS)
        self.filter.currentTextChanged.connect(self.refresh)
        layout.addWidget(self.filter)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Type", "Severity", "Message", "Subject"]
        )
        layout.addWidget(self.table)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        self.refresh()

    def refresh(self, *_args) -> None:
        events = self.database.events(EVENT_FILTERS[self.filter.currentText()])
        self.table.setRowCount(len(events))
        for row, event in enumerate(events):
            for column, key in enumerate(
                ("timestamp", "event_type", "severity", "message", "subject")
            ):
                self.table.setItem(
                    row, column, QTableWidgetItem(str(event.get(key) or ""))
                )
