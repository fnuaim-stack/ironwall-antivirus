from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ironwall.core.models import ScanResult, ScanStatus
from ironwall.quarantine.manager import QuarantineManager
from ironwall.services.scan_service import ScanService


class ScanSignals(QObject):
    result = Signal(object)
    progress = Signal(str, int)
    complete = Signal(dict)


class ScanPage(QWidget):
    def __init__(self, service: ScanService, quarantine: QuarantineManager) -> None:
        super().__init__()
        self.service = service
        self.quarantine = quarantine
        self.signals = ScanSignals()
        self._running = False

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        for name, action in (
            ("Quick Scan", self.quick),
            ("Custom Folder", self.folder),
            ("Scan File", self.file),
            ("Stop Scan", self.service.stop),
        ):
            button = QPushButton(name)
            button.clicked.connect(action)
            controls.addWidget(button)
        layout.addLayout(controls)

        self.status = QLabel("Ready")
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Status", "File", "Threat", "Reason", "Actions"]
        )
        layout.addWidget(self.table)

        self.signals.result.connect(self.add_result)
        self.signals.progress.connect(self.set_progress)
        self.signals.complete.connect(self.done)

    def _run(self, paths: list[Path]) -> None:
        if self._running:
            QMessageBox.information(self, "IronWall", "A scan is already running.")
            return
        if not paths:
            QMessageBox.information(
                self, "IronWall", "No accessible quick-scan folders were found."
            )
            return
        self._running = True
        self.table.setRowCount(0)
        self.status.setText("Scanning…")

        def work() -> None:
            count = 0

            def report(result: ScanResult) -> None:
                nonlocal count
                count += 1
                self.signals.result.emit(result)
                self.signals.progress.emit(result.path, count)

            self.signals.complete.emit(self.service.scan_paths(paths, report))

        threading.Thread(target=work, name="IronWallScan", daemon=True).start()

    def quick(self) -> None:
        self._run(self.service.quick_scan_paths())

    def folder(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "Select folder")
        if value:
            self._run([Path(value)])

    def file(self) -> None:
        value, _ = QFileDialog.getOpenFileName(self, "Select file")
        if value:
            self._run([Path(value)])

    def set_progress(self, path: str, count: int) -> None:
        self.status.setText(f"Scanning {count} files — current: {path}")

    def done(self, totals: dict) -> None:
        self._running = False
        state = "Stopped" if totals.get("stopped") else "Completed"
        self.status.setText(
            f"{state} in {totals['elapsed_seconds']}s — {totals['files_scanned']} files, "
            f"{totals['detections']} detections, {totals['suspicious']} suspicious, "
            f"{totals['errors']} errors"
        )

    def add_result(self, result: ScanResult) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = (
            result.status.value,
            result.file_name,
            result.threat_name or "—",
            "; ".join(result.reasons) or "—",
        )
        for column, value in enumerate(values):
            self.table.setItem(row, column, QTableWidgetItem(value))

        actions = QWidget()
        action_layout = QHBoxLayout(actions)
        action_layout.setContentsMargins(0, 0, 0, 0)
        details = QPushButton("Details")
        details.clicked.connect(lambda _, item=result: self.show_details(item))
        action_layout.addWidget(details)
        if result.status in {ScanStatus.DETECTED, ScanStatus.SUSPICIOUS}:
            quarantine = QPushButton("Quarantine")
            quarantine.clicked.connect(
                lambda _, item=result: self.quarantine_file(item)
            )
            action_layout.addWidget(quarantine)
        self.table.setCellWidget(row, 4, actions)

    def show_details(self, result: ScanResult) -> None:
        scanners = ", ".join(result.scanners) or "None"
        QMessageBox.information(
            self,
            "Scan details",
            f"Path: {result.path}\nSHA-256: {result.sha256 or 'Unavailable'}\n"
            f"Size: {result.file_size} bytes\nScanners: {scanners}\n"
            f"Duration: {result.duration_ms:.2f} ms",
        )

    def quarantine_file(self, result: ScanResult) -> None:
        try:
            self.quarantine.quarantine(result)
            QMessageBox.information(self, "IronWall", f"Quarantined {result.file_name}")
        except Exception as exc:  # noqa: BLE001 - UI error boundary
            QMessageBox.warning(self, "IronWall", f"Could not quarantine file: {exc}")
