# IronWall Antivirus

IronWall Antivirus is an educational Windows-focused antivirus and endpoint-monitoring application. It provides local on-demand scanning, explainable heuristic checks, EICAR detection, SQLite-backed events, and safe quarantine/restore workflows. It is not a replacement for Windows Defender or an enterprise endpoint security product.

## Features

- SHA-256 local rule scanning and standard EICAR test-file recognition
- Explainable double-extension, temporary-directory, startup-script, and PE static heuristics
- Optional YARA and PE providers that fail gracefully when unavailable
- On-demand quick, folder, and single-file scans in a background thread
- Quarantine, restore, and permanent-delete backend operations
- Real-time watchdog file monitoring and psutil process-monitoring services
- PySide6 desktop interface with scan, quarantine, and event views

## Run

On Windows with Python 3.11+:

```powershell
py -m pip install -r requirements.txt
py -m ironwall.main
```

User data, logs, settings, and quarantine files are stored in `%LOCALAPPDATA%\IronWall`.

## Build

Run `scripts\build_windows.ps1`. The output is `dist\IronWall-Antivirus\IronWall-Antivirus.exe`.

## Testing in Windows Sandbox

See [sandbox/README.md](sandbox/README.md) for a safe EICAR-based testing checklist. Do not use live malware.
