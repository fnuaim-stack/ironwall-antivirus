from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from ironwall.utils.paths import rules_dir, user_rules_dir

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

    def __init__(
        self,
        database_path: Path | None = None,
        user_database_path: Path | None = None,
    ) -> None:
        self.database_path = database_path or rules_dir() / "hashes.json"
        self.user_database_path = user_database_path or user_rules_dir() / "hashes.json"
        self._revision: tuple | None = None
        self._hashes: dict[str, dict] = {}
        self.errors: list[str] = []
        self._lock = threading.RLock()

    def _load(self) -> None:
        with self._lock:
            revision = self.revision()
            if revision == self._revision:
                return
            hashes: dict[str, dict] = {}
            errors = []
            for path in (self.database_path, self.user_database_path):
                if not path.exists() and path == self.user_database_path:
                    continue
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    entries = data.get("hashes") if isinstance(data, dict) else data
                    if not isinstance(entries, list):
                        raise TypeError("expected a list of hashes")
                    parsed: dict[str, dict] = {}
                    for entry in entries:
                        if not isinstance(entry, dict):
                            raise TypeError("hash entries must be objects")
                        digest = entry.get("hash", "")
                        if (
                            not isinstance(digest, str)
                            or len(digest) != 64
                            or any(c not in "0123456789abcdefABCDEF" for c in digest)
                            or not isinstance(entry.get("threat_name"), str)
                        ):
                            raise ValueError("invalid SHA-256 or threat name")
                        parsed[digest.lower()] = entry
                    hashes.update(parsed)
                except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
                    errors.append(f"{path.name}: {exc}")
            self._hashes, self.errors, self._revision = hashes, errors, revision

    def revision(self) -> tuple:
        result = []
        for path in (self.database_path, self.user_database_path):
            try:
                stat = path.stat()
                result.append((str(path), stat.st_mtime_ns, stat.st_size))
            except OSError:
                result.append((str(path), -1, -1))
        return tuple(result)

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

    def refresh(self) -> None:
        self._load()
