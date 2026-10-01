from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QWidget,
)

from ironwall.core.config import Settings


class SettingsPage(QWidget):
    def __init__(
        self,
        settings: Settings,
        apply_settings: Callable[..., None],
        yara_available: bool,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.apply_settings = apply_settings

        form = QFormLayout(self)
        self.realtime = QCheckBox()
        self.realtime.setChecked(settings.realtime_enabled)
        self.temp = QCheckBox()
        self.temp.setChecked(settings.scan_temporary_files)
        self.heuristic = QCheckBox()
        self.heuristic.setChecked(settings.heuristics_enabled)
        self.yara = QCheckBox()
        self.yara.setChecked(settings.yara_enabled)
        self.yara.setEnabled(yara_available)
        self.maximum = QSpinBox()
        self.maximum.setRange(1, 4096)
        self.maximum.setValue(settings.maximum_file_size_mb)
        self.quarantine = QLineEdit(settings.quarantine_location)

        quarantine_row = QWidget()
        quarantine_layout = QHBoxLayout(quarantine_row)
        quarantine_layout.setContentsMargins(0, 0, 0, 0)
        quarantine_layout.addWidget(self.quarantine)
        browse = QPushButton("Browse")
        browse.clicked.connect(self.choose_quarantine_location)
        quarantine_layout.addWidget(browse)

        for name, widget in (
            ("Real-time protection", self.realtime),
            ("Scan temporary files", self.temp),
            ("Enable heuristics", self.heuristic),
            ("Enable YARA", self.yara),
            ("Maximum file size (MB)", self.maximum),
            ("Quarantine location", quarantine_row),
        ):
            form.addRow(name, widget)
        provider = (
            "Available" if yara_available else "Unavailable (install yara-python)"
        )
        form.addRow("YARA provider", QLabel(provider))
        save = QPushButton("Save settings")
        save.clicked.connect(self.persist)
        form.addRow(save)

    def refresh_from_settings(self) -> None:
        self.realtime.setChecked(self.settings.realtime_enabled)
        self.temp.setChecked(self.settings.scan_temporary_files)
        self.heuristic.setChecked(self.settings.heuristics_enabled)
        self.yara.setChecked(self.settings.yara_enabled and self.yara.isEnabled())
        self.maximum.setValue(self.settings.maximum_file_size_mb)
        self.quarantine.setText(self.settings.quarantine_location)

    def choose_quarantine_location(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "Choose quarantine location")
        if value:
            self.quarantine.setText(value)

    def persist(self) -> None:
        location = self.quarantine.text().strip()
        if not location:
            QMessageBox.warning(self, "IronWall", "Choose a quarantine location.")
            return
        try:
            self.apply_settings(
                realtime_enabled=self.realtime.isChecked(),
                scan_temporary_files=self.temp.isChecked(),
                heuristics_enabled=self.heuristic.isChecked(),
                yara_enabled=self.yara.isChecked() and self.yara.isEnabled(),
                maximum_file_size_mb=self.maximum.value(),
                quarantine_location=location,
            )
        except Exception as exc:  # noqa: BLE001 - UI error boundary
            QMessageBox.warning(self, "IronWall", f"Could not save settings: {exc}")
            return
        QMessageBox.information(self, "IronWall", "Settings saved and applied.")
