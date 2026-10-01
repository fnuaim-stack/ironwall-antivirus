from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from ironwall.utils.paths import rules_dir

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# The canonical EICAR content is checked directly, since harmless text editors may add a newline.
EICAR_MARKER = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def contains_eicar(path: Path, chunk_size: int = 64 * 1024) -> bool:
    """Find the harmless EICAR marker without loading the entire file."""
    overlap = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            data = overlap + chunk
            if EICAR_MARKER in data:
                return True
            overlap = data[-(len(EICAR_MARKER) - 1) :]
    return False


class HashScanner:
    name = "hash"

    def __init__(self, database_path: Path | None = None) -> None:
        self.database_path = database_path or rules_dir() / "hashes.json"
        self._mtime: float | None = None
        self._hashes: dict[str, dict] = {}
        self._lock = threading.RLock()

    def _load(self) -> None:
        with self._lock:
            try:
                mtime = self.database_path.stat().st_mtime
                if mtime == self._mtime:
                    return
                data = json.loads(self.database_path.read_text(encoding="utf-8"))
                entries = data.get("hashes", data) if isinstance(data, dict) else data
                self._hashes = {
                    entry["hash"].lower(): entry
                    for entry in entries
                    if isinstance(entry, dict)
                    and isinstance(entry.get("hash"), str)
                    and len(entry["hash"]) == 64
                }
                self._mtime = mtime
            except (OSError, json.JSONDecodeError, KeyError, TypeError):
                self._hashes, self._mtime = {}, None

    def scan(self, path: Path, sha256: str | None = None) -> dict | None:
        self._load()
        digest = sha256 or sha256_file(path)
        with self._lock:
            entry = self._hashes.get(digest.lower())
        if entry:
            return {**entry, "sha256": digest}
        if contains_eicar(path):
            return {
                "threat_name": "EICAR-Test-File",
                "severity": "Test/High",
                "description": "Harmless standard antivirus test file.",
                "sha256": digest,
            }
        return None
