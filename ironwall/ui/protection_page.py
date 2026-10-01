from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ironwall.core.config import Settings
from ironwall.monitoring.file_monitor import FileMonitor
from ironwall.monitoring.process_monitor import ProcessMonitor
from ironwall.quarantine.manager import QuarantineManager


class ProtectionSignals(QObject):
    detected = Signal(object)


class ProtectionPage(QWidget):
    def __init__(
        self,
        engine,
        database,
        settings: Settings,
        quarantine: QuarantineManager,
        save: Callable[[], None],
    ) -> None:
        super().__init__()
        self.settings = settings
        self.quarantine = quarantine
        self.save = save
        self.signals = ProtectionSignals()
        self.file_monitor = FileMonitor(engine, database, self.signals.detected.emit)
        self.process_monitor = ProcessMonitor(engine, database)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Real-Time Protection</h2>"))
        self.state = QLabel()
        layout.addWidget(self.state)
        self.folders = QListWidget()
        layout.addWidget(self.folders)

        controls = QHBoxLayout()
        for name, action in (
            ("Add folder", self.add_folder),
            ("Remove selected", self.remove_folder),
            ("Enable", self.start),
            ("Disable", self.stop),
        ):
            button = QPushButton(name)
            button.clicked.connect(action)
            controls.addWidget(button)
        layout.addLayout(controls)

        layout.addWidget(QLabel("<h3>Recent real-time detections</h3>"))
        self.detections = QTableWidget(0, 4)
        self.detections.setHorizontalHeaderLabels(
            ["Threat", "File", "Reason", "Action"]
        )
        layout.addWidget(self.detections)
        for event in reversed(database.events("REALTIME_DETECTION", limit=20)):
            self._add_detection_row(
                event.get("message") or "Detection",
                event.get("subject") or "",
                event.get("details") or "",
            )

        self.signals.detected.connect(self.detected)
        self.refresh()

    def refresh(self) -> None:
        self.folders.clear()
        self.folders.addItems(self.settings.monitored_directories)
        state = "enabled" if self.settings.realtime_enabled else "disabled"
        self.state.setText(f"Protection {state}")

    def add_folder(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "Monitor folder")
        if value and value not in self.settings.monitored_directories:
            self.settings.monitored_directories.append(value)
            self.save()
            self._restart_file_monitor()
            self.refresh()

    def remove_folder(self) -> None:
        row = self.folders.currentRow()
        if row >= 0:
            self.settings.monitored_directories.pop(row)
            self.save()
            self._restart_file_monitor()
            self.refresh()

    def _restart_file_monitor(self) -> None:
        if self.settings.realtime_enabled:
            self.file_monitor.stop()
            errors = self.file_monitor.start(self.settings.monitored_directories)
            if errors:
                self.state.setText("Protection enabled — " + "; ".join(errors))

    def start(self) -> None:
        errors = self.file_monitor.start(self.settings.monitored_directories)
        self.process_monitor.start()
        self.settings.realtime_enabled = True
        self.save()
        self.state.setText(
            "Protection enabled" + (f" — {'; '.join(errors)}" if errors else "")
        )

    def stop(self) -> None:
        self.file_monitor.stop()
        self.process_monitor.stop()
        self.settings.realtime_enabled = False
        self.save()
        self.refresh()

    def detected(self, result) -> None:
        self.state.setText(f"Detection: {result.threat_name} — {result.file_name}")
        self._add_detection_row(
            result.threat_name or "Detected threat",
            result.path,
            "; ".join(result.reasons),
            result,
        )

    def _add_detection_row(
        self, threat: str, path: str, reason: str, result=None
    ) -> None:
        row = self.detections.rowCount()
        self.detections.insertRow(row)
        for column, value in enumerate((threat, path, reason)):
            self.detections.setItem(row, column, QTableWidgetItem(value))
        if result is not None:
            button = QPushButton("Quarantine")
            button.clicked.connect(lambda _, item=result: self.quarantine_file(item))
            self.detections.setCellWidget(row, 3, button)

    def quarantine_file(self, result) -> None:
        try:
            self.quarantine.quarantine(result)
            QMessageBox.information(self, "IronWall", f"Quarantined {result.file_name}")
        except Exception as exc:  # noqa: BLE001 - UI error boundary
            QMessageBox.warning(self, "IronWall", f"Could not quarantine file: {exc}")

    def shutdown(self) -> None:
        self.file_monitor.stop()
        self.process_monitor.stop()
