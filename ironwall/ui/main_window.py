from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QListWidget)

from ironwall.core.config import ConfigManager
from ironwall.core.models import ScanResult, ScanStatus
from ironwall.detection.scanner import ScanningEngine
from ironwall.monitoring.file_monitor import FileMonitor
from ironwall.monitoring.process_monitor import ProcessMonitor
from ironwall.quarantine.manager import QuarantineManager
from ironwall.services.scan_service import ScanService
from ironwall.storage.database import Database


class Signals(QObject):
    result = Signal(object)
    complete = Signal(dict)


class ProtectionSignals(QObject):
    detection = Signal(object)


class ScanPage(QWidget):
    def __init__(self, service: ScanService, quarantine: QuarantineManager) -> None:
        super().__init__(); self.service, self.quarantine, self.signals = service, quarantine, Signals(); self.results: list[ScanResult] = []
        layout = QVBoxLayout(self); controls = QHBoxLayout()
        for label, callback in (("Quick Scan", self.quick), ("Custom Folder", self.folder), ("Scan File", self.file), ("Stop Scan", self.service.stop)):
            button = QPushButton(label); button.clicked.connect(callback); controls.addWidget(button)
        layout.addLayout(controls); self.status = QLabel("Ready"); layout.addWidget(self.status)
        self.table = QTableWidget(0, 5); self.table.setHorizontalHeaderLabels(["Status", "File", "Threat", "Reason", "Action"]); layout.addWidget(self.table)
        self.signals.result.connect(self.add_result); self.signals.complete.connect(lambda total: self.status.setText(f"Completed: {total['files_scanned']} files, {total['detections']} detections"))
    def _run(self, paths):
        self.results.clear(); self.table.setRowCount(0); self.status.setText("Scanning…")
        threading.Thread(target=lambda: self.signals.complete.emit(self.service.scan_paths(paths, self.signals.result.emit)), daemon=True).start()
    def quick(self): self._run(self.service.quick_scan_paths())
    def folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select folder")
        if path: self._run([Path(path)])
    def file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path: self._run([Path(path)])
    def add_result(self, result: ScanResult):
        row=self.table.rowCount(); self.table.insertRow(row); self.results.append(result)
        display_status = "SKIPPED" if any(reason.startswith("Skipped:") for reason in result.reasons) else result.status.value
        for col, text in enumerate((display_status, result.file_name, result.threat_name or "—", "; ".join(result.reasons) or "—")):
            self.table.setItem(row,col,QTableWidgetItem(text))
        if result.status in {ScanStatus.DETECTED, ScanStatus.SUSPICIOUS}:
            button=QPushButton("Quarantine"); button.clicked.connect(lambda _, r=result: self._quarantine(r)); self.table.setCellWidget(row,4,button)
    def _quarantine(self, result):
        try: self.quarantine.quarantine(result); QMessageBox.information(self,"IronWall",f"Quarantined {result.file_name}")
        except Exception as exc: QMessageBox.warning(self,"IronWall",f"Could not quarantine file: {exc}")


class EventsPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__(); self.database=database; layout=QVBoxLayout(self); refresh=QPushButton("Refresh"); refresh.clicked.connect(self.refresh); layout.addWidget(refresh); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Time","Type","Severity","Message","Subject"]); layout.addWidget(self.table); self.refresh()
    def refresh(self):
        events=self.database.events(); self.table.setRowCount(len(events))
        for row,event in enumerate(events):
            for col,key in enumerate(("timestamp","event_type","severity","message","subject")): self.table.setItem(row,col,QTableWidgetItem(str(event.get(key) or "")))


class QuarantinePage(QWidget):
    def __init__(self, manager: QuarantineManager, database: Database) -> None:
        super().__init__(); self.manager,self.database=manager,database; layout=QVBoxLayout(self); refresh=QPushButton("Refresh"); refresh.clicked.connect(self.refresh); layout.addWidget(refresh); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Date","File","Threat","Original Path","Action"]); layout.addWidget(self.table); self.refresh()
    def refresh(self):
        entries=self.database.quarantine_entries(); self.table.setRowCount(len(entries))
        for row,e in enumerate(entries):
            for col,key in enumerate(("created_at","id","threat_name","original_path")): self.table.setItem(row,col,QTableWidgetItem(str(e[key])))
            button=QPushButton("Restore"); button.clicked.connect(lambda _, id=e['id']: self.restore(id)); self.table.setCellWidget(row,4,button)
    def restore(self, entry_id):
        try: self.manager.restore(entry_id); self.refresh()
        except Exception as exc: QMessageBox.warning(self,"IronWall",f"Restore failed: {exc}")


class ProtectionPage(QWidget):
    def __init__(self, engine, database, settings, config_manager) -> None:
        super().__init__(); self.engine, self.database, self.settings, self.config_manager = engine, database, settings, config_manager
        self.signals = ProtectionSignals(); self.signals.detection.connect(self.detected)
        self.file_monitor = FileMonitor(engine, database, self.signals.detection.emit); self.process_monitor = ProcessMonitor(engine, database)
        layout=QVBoxLayout(self); layout.addWidget(QLabel("<h2>Real-Time Protection</h2>")); self.state=QLabel("Protection disabled")
        layout.addWidget(self.state); self.folders=QLabel("Monitored folders:\n" + "\n".join(settings.monitored_directories or ["No accessible default folders found"]))
        layout.addWidget(self.folders); buttons=QHBoxLayout(); start=QPushButton("Enable Protection"); stop=QPushButton("Disable Protection"); start.clicked.connect(self.start); stop.clicked.connect(self.stop); buttons.addWidget(start); buttons.addWidget(stop); layout.addLayout(buttons); layout.addStretch()
    def start(self):
        errors=self.file_monitor.start(self.settings.monitored_directories); self.process_monitor.start(); self.settings.realtime_enabled=True; self.config_manager.save(self.settings)
        self.state.setText("Protection enabled" + (" — " + "; ".join(errors) if errors else ""))
    def stop(self):
        self.file_monitor.stop(); self.process_monitor.stop(); self.settings.realtime_enabled=False; self.config_manager.save(self.settings); self.state.setText("Protection disabled")
    def detected(self, result):
        self.state.setText(f"Detection: {result.threat_name} in {result.file_name}")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__(); self.setWindowTitle("IronWall Antivirus"); self.resize(1050, 650)
        config_manager=ConfigManager(); settings=config_manager.load(); database=Database(); engine=ScanningEngine(settings.maximum_file_size_mb, settings.heuristics_enabled, settings.yara_enabled); quarantine=QuarantineManager(database, Path(settings.quarantine_location))
        pages=QStackedWidget(); scan=ScanPage(ScanService(engine,database),quarantine)
        dashboard=QWidget(); d=QVBoxLayout(dashboard); d.addWidget(QLabel("<h1>IronWall Antivirus</h1><h3>Protection status: local monitoring available</h3><p>Educational endpoint monitoring. It complements, not replaces, Windows Defender.</p>")); quick=QPushButton("Start Quick Scan"); quick.clicked.connect(lambda: pages.setCurrentWidget(scan)); d.addWidget(quick); d.addStretch()
        protection=ProtectionPage(engine, database, settings, config_manager)
        settings_page=QWidget(); s=QVBoxLayout(settings_page); s.addWidget(QLabel("<h2>Settings</h2><p>Settings are stored under your local IronWall application-data folder.</p>")); s.addStretch()
        items=[("Dashboard",dashboard),("Scan",scan),("Real-Time Protection",protection),("Quarantine",QuarantinePage(quarantine,database)),("Security Events",EventsPage(database)),("Settings",settings_page)]
        sidebar=QListWidget(); sidebar.addItems([x[0] for x in items]); [pages.addWidget(x[1]) for x in items]; sidebar.currentRowChanged.connect(pages.setCurrentIndex); sidebar.setCurrentRow(0)
        container=QWidget(); layout=QHBoxLayout(container); layout.addWidget(sidebar,1); layout.addWidget(pages,5); self.setCentralWidget(container)


def run() -> int:
    app=QApplication.instance() or QApplication([]); window=MainWindow(); window.show(); return app.exec()
