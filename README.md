# IronWall Antivirus

IronWall Antivirus is an educational Windows-focused antivirus and endpoint-monitoring application. It provides local on-demand scanning, explainable heuristic checks, EICAR detection, SQLite-backed events, and safe quarantine/restore workflows. It is not a replacement for Windows Defender or an enterprise endpoint security product.

## Features

- SHA-256 local rule scanning, standard EICAR recognition, and published WannaCry sample hashes
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

Alternatively, run `scripts\setup_windows.ps1 -Launch` to create a virtual environment, install dependencies, and start IronWall.

User data, logs, settings, and quarantine files are stored in `%LOCALAPPDATA%\IronWall`.

## Build

Run `scripts\build_windows.ps1`. The committed PyInstaller spec produces `dist\IronWall-Antivirus.exe`.
The build script also runs a non-interactive startup smoke test against the packaged executable.
Successful GitHub Actions runs publish the EXE as the `IronWall-Antivirus-Windows` artifact for 14 days.

## Tests

```powershell
py -m pytest tests -q
```

YARA is optional at runtime. If `yara-python` cannot be installed, IronWall continues with hash, heuristic, and PE scanning and reports YARA as unavailable in Settings. The local database detects the listed exact WannaCry samples by SHA-256, and the conservative YARA rule can detect related files carrying several known static indicators. This is useful portfolio-grade protection, not a guarantee against every WannaCry variant or malware family.

## Testing in Windows Sandbox

See [sandbox/README.md](sandbox/README.md) for an isolated, repeatable checklist using EICAR and a harmless WannaCry signature fixture. Do not use live malware or disable Windows Defender.
