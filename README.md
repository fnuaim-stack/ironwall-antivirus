# IronWall Antivirus

**Current release: Alpha v1.0.0**

IronWall Antivirus is a Windows antivirus and endpoint-monitoring project built for learning and testing. It can scan files, monitor changes, detect test threats, quarantine files, and show security events.

## Features

- Quick, folder, and single-file scans
- SHA-256, heuristic, PE, YARA, and optional ClamAV checks
- Real-time file and process monitoring
- Quarantine and restore
- Security events and simple desktop UI

## Download

Download **IronWall-Antivirus.exe** from the GitHub Releases page and run it on Windows.

The EXE is currently unsigned, so Windows may show a SmartScreen warning.

## Run from source

Requires Python 3.11+:

```powershell
py -m pip install -r requirements.txt
py -m ironwall.main
```

## Test in Windows Sandbox

1. Enable **Windows Sandbox** in Windows Features and restart if needed.
2. Create `C:\IronWallSandbox`.
3. Put these files inside it:
   - `IronWall-Antivirus.exe`
   - `sandbox\IronWall-Isolated.wsb`
   - `sandbox\create_test_samples.ps1`
4. Double-click `IronWall-Isolated.wsb`.
5. In Sandbox, copy the EXE from the mapped **IronWall** folder to the Desktop and run it.
6. Follow the short test steps in [sandbox/README.md](sandbox/README.md).

Keep Windows Defender enabled. The included samples are harmless test fixtures.

## Build

```powershell
scripts\build_windows.ps1
```

IronWall is an educational project and does not replace Windows Defender or an enterprise antivirus product.
