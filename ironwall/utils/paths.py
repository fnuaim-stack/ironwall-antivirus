from __future__ import annotations

import os
import tempfile
from pathlib import Path


def app_data_dir() -> Path:
    """Return a persistent per-user directory, including from PyInstaller."""
    override = os.environ.get("IRONWALL_DATA_DIR")
    if override:
        path = Path(override)
        path.mkdir(parents=True, exist_ok=True)
        return path
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    base = Path(root) if root else Path.home() / ".local" / "share"
    path = base / "IronWall"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        if os.name == "nt":
            raise
        # Useful for locked-down test runners; Windows uses LOCALAPPDATA above.
        path = Path(tempfile.gettempdir()) / "IronWall"
        path.mkdir(parents=True, exist_ok=True)
    return path


def rules_dir() -> Path:
    if getattr(__import__("sys"), "frozen", False):
        return Path(__import__("sys")._MEIPASS) / "rules"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[2] / "rules"
