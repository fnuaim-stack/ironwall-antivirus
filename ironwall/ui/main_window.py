from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox, QPushButton, QSpinBox, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ironwall.core.config import ConfigManager, Settings
from ironwall.core.models import ScanResult, ScanStatus
from ironwall.detection.scanner import ScanningEngine
from ironwall.monitoring.file_monitor import FileMonitor
from ironwall.monitoring.process_monitor import ProcessMonitor
from ironwall.quarantine.manager import QuarantineManager
from ironwall.services.scan_service import ScanService
from ironwall.storage.database import Database


class Signals(QObject):
    result = Signal(object); progress = Signal(str, int); complete = Signal(dict); detected = Signal(object)


class DashboardPage(QWidget):
    def __init__(self, database: Database, open_scan) -> None:
        super().__init__(); self.database=database; layout=QVBoxLayout(self); layout.addWidget(QLabel("<h1>IronWall Antivirus</h1>")); self.summary=QLabel(); layout.addWidget(self.summary)
        quick=QPushButton("Quick Scan"); quick.clicked.connect(open_scan); layout.addWidget(quick); layout.addWidget(QLabel("<h3>Recent security events</h3>")); self.events=QTableWidget(0,3); self.events.setHorizontalHeaderLabels(["Time", "Severity", "Message"]); layout.addWidget(self.events); refresh=QPushButton("Refresh dashboard"); refresh.clicked.connect(self.refresh); layout.addWidget(refresh); self.refresh()
    def refresh(self):
        counts=self.database.dashboard_counts(); last=self.database.last_scan(); last_label=last["completed_at"] if last else "Never"
        self.summary.setText(f"Protection status: local monitoring available\nLast scan: {last_label}\nThreats detected: {counts['detections']}\nFiles quarantined: {counts['quarantined']}")
        rows=self.database.events(limit=8); self.events.setRowCount(len(rows))
        for row,event in enumerate(rows):
            for col,key in enumerate(("timestamp","severity","message")): self.events.setItem(row,col,QTableWidgetItem(str(event.get(key) or "")))


class ScanPage(QWidget):
    def __init__(self, service: ScanService, quarantine: QuarantineManager) -> None:
        super().__init__(); self.service,self.quarantine,self.signals=service,quarantine,Signals(); layout=QVBoxLayout(self); controls=QHBoxLayout()
        for name, action in (("Quick Scan",self.quick),("Custom Folder",self.folder),("Scan File",self.file),("Stop Scan",service.stop)):
            button=QPushButton(name); button.clicked.connect(action); controls.addWidget(button)
        layout.addLayout(controls); self.status=QLabel("Ready"); layout.addWidget(self.status)
        self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Status","File","Threat","Reason","Action"]); layout.addWidget(self.table)
        self.signals.result.connect(self.add_result); self.signals.progress.connect(self.set_progress); self.signals.complete.connect(self.done)
    def _run(self, paths):
        self.table.setRowCount(0); self.status.setText("Scanning…")
        def work():
            count=0
            def report(result):
                nonlocal count; count += 1; self.signals.result.emit(result); self.signals.progress.emit(result.path,count)
            self.signals.complete.emit(self.service.scan_paths(paths,report))
        threading.Thread(target=work,daemon=True).start()
    def quick(self): self._run(self.service.quick_scan_paths())
    def folder(self):
        value=QFileDialog.getExistingDirectory(self,"Select folder")
        if value: self._run([Path(value)])
    def file(self):
        value,_=QFileDialog.getOpenFileName(self,"Select file")
        if value: self._run([Path(value)])
    def set_progress(self,path,count): self.status.setText(f"Scanning {count} files — current: {path}")
    def done(self,total): self.status.setText(f"Completed in {total['elapsed_seconds']}s — {total['files_scanned']} files, {total['detections']} detections, {total['suspicious']} suspicious")
    def add_result(self,result: ScanResult):
        row=self.table.rowCount(); self.table.insertRow(row)
        for col,text in enumerate((result.status.value,result.file_name,result.threat_name or "—","; ".join(result.reasons) or "—")): self.table.setItem(row,col,QTableWidgetItem(text))
        if result.status in {ScanStatus.DETECTED,ScanStatus.SUSPICIOUS}:
            button=QPushButton("Quarantine"); button.clicked.connect(lambda _,r=result:self.quarantine_file(r)); self.table.setCellWidget(row,4,button)
    def quarantine_file(self,result):
        try: self.quarantine.quarantine(result); QMessageBox.information(self,"IronWall",f"Quarantined {result.file_name}")
        except Exception as exc: QMessageBox.warning(self,"IronWall",f"Could not quarantine file: {exc}")


class ProtectionPage(QWidget):
    def __init__(self, engine, database, settings: Settings, save) -> None:
        super().__init__(); self.settings,self.save=settings,save; self.signals=Signals(); self.monitor=FileMonitor(engine,database,self.signals.detected.emit); self.process=ProcessMonitor(engine,database)
        layout=QVBoxLayout(self); layout.addWidget(QLabel("<h2>Real-Time Protection</h2>")); self.state=QLabel(); layout.addWidget(self.state); self.folders=QListWidget(); layout.addWidget(self.folders)
        row=QHBoxLayout(); add=QPushButton("Add folder"); remove=QPushButton("Remove selected"); enable=QPushButton("Enable"); disable=QPushButton("Disable"); [row.addWidget(x) for x in (add,remove,enable,disable)]; layout.addLayout(row)
        add.clicked.connect(self.add_folder); remove.clicked.connect(self.remove_folder); enable.clicked.connect(self.start); disable.clicked.connect(self.stop); self.signals.detected.connect(self.detected); self.refresh()
    def refresh(self): self.folders.clear(); self.folders.addItems(self.settings.monitored_directories); self.state.setText("Protection enabled" if self.settings.realtime_enabled else "Protection disabled")
    def add_folder(self):
        value=QFileDialog.getExistingDirectory(self,"Monitor folder")
        if value and value not in self.settings.monitored_directories: self.settings.monitored_directories.append(value); self.save(); self.refresh()
    def remove_folder(self):
        row=self.folders.currentRow()
        if row >= 0: self.settings.monitored_directories.pop(row); self.save(); self.refresh()
    def start(self):
        errors=self.monitor.start(self.settings.monitored_directories); self.process.start(); self.settings.realtime_enabled=True; self.save(); self.state.setText("Protection enabled" + (f" — {len(errors)} folder errors" if errors else ""))
    def stop(self): self.monitor.stop(); self.process.stop(); self.settings.realtime_enabled=False; self.save(); self.refresh()
    def detected(self,result): self.state.setText(f"Detection: {result.threat_name} — {result.file_name}")


class QuarantinePage(QWidget):
    def __init__(self, manager: QuarantineManager, database: Database) -> None:
        super().__init__(); self.manager,self.database=manager,database; layout=QVBoxLayout(self); self.table=QTableWidget(0,6); self.table.setHorizontalHeaderLabels(["Date","File","Threat","Original path","Hash","Actions"]); layout.addWidget(self.table); refresh=QPushButton("Refresh"); refresh.clicked.connect(self.refresh); layout.addWidget(refresh); self.refresh()
    def refresh(self):
        entries=self.database.quarantine_entries(); self.table.setRowCount(len(entries))
        for row,e in enumerate(entries):
            values=(e["created_at"],Path(e["original_path"]).name,e["threat_name"],e["original_path"],e["sha256"])
            for col,value in enumerate(values): self.table.setItem(row,col,QTableWidgetItem(str(value)))
            actions=QWidget(); layout=QHBoxLayout(actions); layout.setContentsMargins(0,0,0,0)
            for name,callback in (("Details",lambda _,x=e:self.details(x)),("Restore",lambda _,x=e["id"]:self.restore(x)),("Delete",lambda _,x=e["id"]:self.delete(x))): button=QPushButton(name); button.clicked.connect(callback); layout.addWidget(button)
            self.table.setCellWidget(row,5,actions)
    def restore(self,entry_id):
        try: self.manager.restore(entry_id); self.refresh()
        except FileExistsError:
            destination,_=QFileDialog.getSaveFileName(self,"Choose restore destination")
            if destination:
                try: self.manager.restore(entry_id,Path(destination)); self.refresh()
                except Exception as exc: QMessageBox.warning(self,"IronWall",str(exc))
        except Exception as exc: QMessageBox.warning(self,"IronWall",str(exc))
    def delete(self,entry_id):
        if QMessageBox.question(self,"Permanently delete","Permanently delete this quarantined file?") == QMessageBox.Yes:
            try: self.manager.delete(entry_id); self.refresh()
            except Exception as exc: QMessageBox.warning(self,"IronWall",str(exc))
    def details(self, entry): QMessageBox.information(self,"Quarantine details",f"Threat: {entry['threat_name']}\nHash: {entry['sha256']}\nReason: {entry['reason']}")


class EventsPage(QWidget):
    def __init__(self,database:Database) -> None:
        super().__init__(); self.database=database; layout=QVBoxLayout(self); self.filter=QListWidget(); self.filter.addItems(["All","Detection","Scanning","Monitoring","Process","Quarantine","Errors"]); self.filter.setMaximumHeight(80); layout.addWidget(self.filter); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Time","Type","Severity","Message","Subject"]); layout.addWidget(self.table); self.filter.currentTextChanged.connect(self.refresh); self.filter.setCurrentRow(0); self.refresh()
    def refresh(self,*_):
        choices={"Detection":("THREAT_DETECTED","PROCESS_DETECTION"),"Scanning":("SCAN_STARTED","SCAN_COMPLETED","FILE_SCANNED"),"Monitoring":("REALTIME_DETECTION",),"Process":("PROCESS_STARTED","PROCESS_DETECTION"),"Quarantine":("FILE_QUARANTINED","FILE_RESTORED"),"Errors":("ERROR",)}; rows=self.database.events(choices.get(self.filter.currentItem().text()) if self.filter.currentItem() else None)
        self.table.setRowCount(len(rows))
        for row,event in enumerate(rows):
            for col,key in enumerate(("timestamp","event_type","severity","message","subject")): self.table.setItem(row,col,QTableWidgetItem(str(event.get(key) or "")))


class SettingsPage(QWidget):
    def __init__(self, settings: Settings, save) -> None:
        super().__init__(); self.settings,self.save=settings,save; form=QFormLayout(self); self.realtime=QCheckBox(); self.realtime.setChecked(settings.realtime_enabled); self.temp=QCheckBox(); self.temp.setChecked(settings.scan_temporary_files); self.heuristic=QCheckBox(); self.heuristic.setChecked(settings.heuristics_enabled); self.yara=QCheckBox(); self.yara.setChecked(settings.yara_enabled); self.maximum=QSpinBox(); self.maximum.setRange(1,4096); self.maximum.setValue(settings.maximum_file_size_mb); self.quarantine=QLineEdit(settings.quarantine_location)
        for name,widget in (("Real-time protection",self.realtime),("Scan temporary files",self.temp),("Enable heuristics",self.heuristic),("Enable YARA",self.yara),("Maximum file size (MB)",self.maximum),("Quarantine location",self.quarantine)): form.addRow(name,widget)
        button=QPushButton("Save settings"); button.clicked.connect(self.persist); form.addRow(button)
    def persist(self):
        self.settings.realtime_enabled=self.realtime.isChecked(); self.settings.scan_temporary_files=self.temp.isChecked(); self.settings.heuristics_enabled=self.heuristic.isChecked(); self.settings.yara_enabled=self.yara.isChecked(); self.settings.maximum_file_size_mb=self.maximum.value(); self.settings.quarantine_location=self.quarantine.text().strip(); self.save(); QMessageBox.information(self,"IronWall","Settings saved. Scanner options apply to newly created scan engines after restart.")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__(); self.setWindowTitle("IronWall Antivirus"); self.resize(1100,700); self.config=ConfigManager(); self.settings=self.config.load(); self.database=Database(); self.engine=ScanningEngine(self.settings.maximum_file_size_mb,self.settings.heuristics_enabled,self.settings.yara_enabled); self.quarantine=QuarantineManager(self.database,Path(self.settings.quarantine_location))
        pages=QStackedWidget(); scan=ScanPage(ScanService(self.engine,self.database,self.settings.scan_temporary_files),self.quarantine); dashboard=DashboardPage(self.database,lambda:pages.setCurrentWidget(scan)); protection=ProtectionPage(self.engine,self.database,self.settings,lambda:self.config.save(self.settings)); entries=[("Dashboard",dashboard),("Scan",scan),("Real-Time Protection",protection),("Quarantine",QuarantinePage(self.quarantine,self.database)),("Security Events",EventsPage(self.database)),("Settings",SettingsPage(self.settings,lambda:self.config.save(self.settings)))]
        sidebar=QListWidget(); sidebar.addItems([name for name,_ in entries]); [pages.addWidget(page) for _,page in entries]; sidebar.currentRowChanged.connect(pages.setCurrentIndex); sidebar.setCurrentRow(0); root=QWidget(); layout=QHBoxLayout(root); layout.addWidget(sidebar,1); layout.addWidget(pages,5); self.setCentralWidget(root)
        if self.settings.realtime_enabled: protection.start()

def run() -> int:
    app=QApplication.instance() or QApplication([]); window=MainWindow(); window.show(); return app.exec()
