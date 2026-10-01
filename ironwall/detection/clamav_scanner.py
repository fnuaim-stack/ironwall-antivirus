from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class ClamAVScanner:
    """Optional local ClamAV CLI provider; never executes the scanned file."""

    name = "clamav"

    def __init__(self, executable: str | None = None, timeout: int = 60) -> None:
        configured = executable or os.environ.get("IRONWALL_CLAMSCAN_PATH")
        self.executable = configured or shutil.which("clamscan")
        self.available = bool(self.executable)
        self.timeout = timeout

    def scan(self, path: Path) -> str | None:
        if not self.available:
            return None
        try:
            completed = subprocess.run(
                [
                    self.executable,
                    "--no-summary",
                    "--stdout",
                    "--infected",
                    str(path.resolve()),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("ClamAV scan timed out") from exc
        except OSError as exc:
            raise RuntimeError(f"ClamAV could not start: {exc}") from exc
        if completed.returncode == 0:
            return None
        if completed.returncode == 1:
            for line in completed.stdout.splitlines():
                if line.endswith(" FOUND") and ": " in line:
                    return line.rpartition(": ")[2].removesuffix(" FOUND")
            raise RuntimeError("ClamAV reported a detection without a signature name")
        message = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"ClamAV could not scan the file: {message[:300]}")
