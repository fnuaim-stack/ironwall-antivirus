# IronWall Antivirus

IronWall Antivirus is an educational Windows-focused antivirus and endpoint-monitoring application. It provides local on-demand scanning, explainable heuristic checks, EICAR detection, SQLite-backed events, and safe quarantine/restore workflows. It is not a replacement for Windows Defender or an enterprise endpoint security product.

## Features

- SHA-256 local rule scanning and standard EICAR test-file recognition
- Explainable double-extension, temporary-directory, startup-script, and PE static heuristics
- Optional YARA provider and static PE metadata/heuristics
- On-demand quick, folder, and single-file scans in a background thread
- Quarantine, restore, and permanent-delete backend operations
- Real-time watchdog file monitoring and psutil process-monitoring services
- PySide6 desktop interface with dashboard, scanning, protection, quarantine, events, and persistent settings

## Run

On Windows with Python 3.11+:

```powershell
py -m pip install -r requirements.txt
# Optional YARA provider:
py -m pip install -r requirements-yara.txt
py -m ironwall.main
```

User data, logs, settings, and quarantine files are stored in `%LOCALAPPDATA%\IronWall`.

## Build

Run `scripts\build_windows.ps1`. The committed PyInstaller spec produces `dist\IronWall-Antivirus.exe`.
The build script also runs a non-interactive startup smoke test against the packaged executable.

## Tests

```powershell
py -m pytest tests -q
```

YARA is optional at runtime. If `yara-python` cannot be installed, IronWall continues with hash, heuristic, and PE scanning and reports YARA as unavailable in Settings.

## Testing in Windows Sandbox

See [sandbox/README.md](sandbox/README.md) for a safe EICAR-based testing checklist. Do not use live malware.
