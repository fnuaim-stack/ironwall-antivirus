from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ironwall.core.models import SecurityEvent
from ironwall.utils.paths import app_data_dir


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or app_data_dir() / "ironwall.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init(self) -> None:
        with self._connect() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp TEXT, event_type TEXT, severity TEXT, source TEXT, subject TEXT, message TEXT, details TEXT);
            CREATE TABLE IF NOT EXISTS scan_sessions (id INTEGER PRIMARY KEY, started_at TEXT, completed_at TEXT, files_scanned INTEGER, detections INTEGER, suspicious INTEGER, errors INTEGER);
            CREATE TABLE IF NOT EXISTS detections (id INTEGER PRIMARY KEY, timestamp TEXT, path TEXT, sha256 TEXT, threat_name TEXT, severity TEXT, reasons TEXT, source TEXT);
            CREATE TABLE IF NOT EXISTS quarantine (id TEXT PRIMARY KEY, created_at TEXT, original_path TEXT, quarantine_path TEXT, threat_name TEXT, sha256 TEXT, file_size INTEGER, reason TEXT);
            """)

    def add_event(self, event: SecurityEvent) -> None:
        with self._connect() as c:
            c.execute(
                "INSERT INTO events(timestamp,event_type,severity,source,subject,message,details) VALUES(?,?,?,?,?,?,?)",
                (
                    event.timestamp,
                    event.event_type.value,
                    event.severity,
                    event.source,
                    event.subject,
                    event.message,
                    event.details,
                ),
            )

    def start_scan_session(self, started_at: str) -> int:
        with self._connect() as c:
            return int(
                c.execute(
                    "INSERT INTO scan_sessions(started_at,files_scanned,detections,suspicious,errors) VALUES(?,?,?,?,?)",
                    (started_at, 0, 0, 0, 0),
                ).lastrowid
            )

    def complete_scan_session(
        self, session_id: int, completed_at: str, totals: dict[str, Any]
    ) -> None:
        with self._connect() as c:
            c.execute(
                "UPDATE scan_sessions SET completed_at=?,files_scanned=?,detections=?,suspicious=?,errors=? WHERE id=?",
                (
                    completed_at,
                    totals["files_scanned"],
                    totals["detections"],
                    totals["suspicious"],
                    totals["errors"],
                    session_id,
                ),
            )

    def last_scan(self) -> dict | None:
        with self._connect() as c:
            row = c.execute(
                "SELECT * FROM scan_sessions WHERE completed_at IS NOT NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def add_detection(self, result, source: str) -> None:
        with self._connect() as c:
            c.execute(
                "INSERT INTO detections(timestamp,path,sha256,threat_name,severity,reasons,source) VALUES(?,?,?,?,?,?,?)",
                (
                    result.timestamp,
                    result.path,
                    result.sha256,
                    result.threat_name,
                    result.severity,
                    "; ".join(result.reasons),
                    source,
                ),
            )

    def dashboard_counts(self) -> dict[str, int]:
        with self._connect() as c:
            return {
                "detections": int(
                    c.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
                ),
                "quarantined": int(
                    c.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]
                ),
            }

    def events(
        self, event_types: str | tuple[str, ...] | None = None, limit: int = 200
    ) -> list[dict]:
        if isinstance(event_types, str):
            event_types = (event_types,)
        where = (
            " WHERE event_type IN (" + ",".join("?" for _ in event_types) + ")"
            if event_types
            else ""
        )
        query = "SELECT * FROM events" + where + " ORDER BY id DESC LIMIT ?"
        args: tuple = (*event_types, limit) if event_types else (limit,)
        with self._connect() as c:
            return [dict(row) for row in c.execute(query, args)]

    def add_quarantine(self, entry: dict) -> None:
        keys = (
            "id",
            "created_at",
            "original_path",
            "quarantine_path",
            "threat_name",
            "sha256",
            "file_size",
            "reason",
        )
        with self._connect() as c:
            c.execute(
                f"INSERT INTO quarantine({','.join(keys)}) VALUES({','.join('?' for _ in keys)})",
                [entry[k] for k in keys],
            )

    def quarantine_entries(self) -> list[dict]:
        with self._connect() as c:
            return [
                dict(row)
                for row in c.execute(
                    "SELECT * FROM quarantine ORDER BY created_at DESC"
                )
            ]

    def quarantine_entry(self, entry_id: str) -> dict | None:
        with self._connect() as c:
            row = c.execute(
                "SELECT * FROM quarantine WHERE id=?", (entry_id,)
            ).fetchone()
            return dict(row) if row else None

    def remove_quarantine(self, entry_id: str) -> None:
        with self._connect() as c:
            c.execute("DELETE FROM quarantine WHERE id=?", (entry_id,))

    def update_quarantine_path(self, entry_id: str, path: str) -> None:
        with self._connect() as c:
            c.execute(
                "UPDATE quarantine SET quarantine_path=? WHERE id=?", (path, entry_id)
            )
