IronWall Antivirus Alpha v1.0.0 is a Windows user-mode antivirus and endpoint-monitoring preview.

Included:

- On-demand file, folder, and quick scans with SHA-256, static heuristics, PE inspection, and YARA.
- Local EICAR and published WannaCry indicators; user-managed hash and YARA rules under `%LOCALAPPDATA%\IronWall\Rules`.
- Optional ClamAV scanning when `clamscan.exe` and an updated signature database are installed separately.
- File and process monitoring, security events, quarantine, and restore.
- A single-file Windows EXE and an inert Windows Sandbox test kit.

The EXE is unsigned. Windows may display a SmartScreen warning. This Alpha does not guarantee detection of arbitrary malware or stop an already running ransomware process before it encrypts files. Live samples were not executed during automated tests. Use an isolated disposable VM for that validation and keep Windows Defender enabled.
