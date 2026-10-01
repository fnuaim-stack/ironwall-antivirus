from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ironwall.quarantine.manager import QuarantineManager
from ironwall.storage.database import Database


class QuarantinePage(QWidget):
    def __init__(self, manager: QuarantineManager, database: Database) -> None:
        super().__init__()
        self.manager = manager
        self.database = database

        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Date", "File", "Threat", "Original path", "Hash", "Actions"]
        )
        layout.addWidget(self.table)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        self.refresh()

    def refresh(self) -> None:
        entries = self.database.quarantine_entries()
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = (
                entry["created_at"],
                Path(entry["original_path"]).name,
                entry["threat_name"],
                entry["original_path"],
                entry["sha256"],
            )
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))

            actions = QWidget()
            action_layout = QHBoxLayout(actions)
            action_layout.setContentsMargins(0, 0, 0, 0)
            callbacks = (
                ("Details", lambda _, item=entry: self.details(item)),
                ("Restore", lambda _, entry_id=entry["id"]: self.restore(entry_id)),
                ("Delete", lambda _, entry_id=entry["id"]: self.delete(entry_id)),
            )
            for name, callback in callbacks:
                button = QPushButton(name)
                button.clicked.connect(callback)
                action_layout.addWidget(button)
            self.table.setCellWidget(row, 5, actions)

    def restore(self, entry_id: str) -> None:
        try:
            self.manager.restore(entry_id)
            self.refresh()
        except FileExistsError:
            destination, _ = QFileDialog.getSaveFileName(
                self, "Choose restore destination"
            )
            if destination:
                try:
                    self.manager.restore(entry_id, Path(destination))
                    self.refresh()
                except Exception as exc:  # noqa: BLE001 - UI error boundary
                    QMessageBox.warning(self, "IronWall", str(exc))
        except Exception as exc:  # noqa: BLE001 - UI error boundary
            QMessageBox.warning(self, "IronWall", str(exc))

    def delete(self, entry_id: str) -> None:
        answer = QMessageBox.question(
            self, "Permanently delete", "Permanently delete this quarantined file?"
        )
        if answer != QMessageBox.Yes:
            return
        try:
            self.manager.delete(entry_id)
            self.refresh()
        except Exception as exc:  # noqa: BLE001 - UI error boundary
            QMessageBox.warning(self, "IronWall", str(exc))

    def details(self, entry: dict) -> None:
        QMessageBox.information(
            self,
            "Quarantine details",
            f"Threat: {entry['threat_name']}\nHash: {entry['sha256']}\nReason: {entry['reason']}",
        )
