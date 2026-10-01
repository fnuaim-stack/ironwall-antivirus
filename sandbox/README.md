# Windows Sandbox test checklist

## Packaged application (recommended)

1. Download the `IronWall-Antivirus-Windows` artifact from the successful GitHub Actions run, or build with `scripts\build_windows.ps1` on Windows.
2. Create `C:\IronWallSandbox` on the host and copy these items into it:
   - `IronWall-Antivirus.exe`
   - `sandbox\create_test_samples.ps1`
3. Double-click `sandbox\IronWall-Isolated.wsb`. The template disables networking and maps `C:\IronWallSandbox` read-only.
4. In Sandbox, copy the EXE to the Desktop before running it. Run the sample script from PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\IronWall\create_test_samples.ps1
   ```

5. In IronWall, scan `Downloads\IronWall-Test-Samples`. Confirm:
   - `eicar.com` is reported as `EICAR-Test-File` if Defender did not intercept it first.
   - `harmless-wannacry-signature-fixture.bin` is reported as `Ransom.Win32.WannaCry` when the YARA provider is packaged.
6. Quarantine and restore a fixture, run Quick Scan, and verify the Security Events page records the actions.
7. Add `Downloads\IronWall-Test-Samples` as a monitored folder, enable real-time protection, copy a fixture into it, and confirm a real-time event appears.

For source testing with Sandbox networking enabled, copy the repository and run `scripts\setup_windows.ps1 -Launch` instead. The setup script installs the optional YARA provider when a compatible wheel is available.

Windows Defender may independently remove EICAR before IronWall opens it; that is expected. Do not disable Defender. Do not download or execute WannaCry or any other live malware for this checklist. The included WannaCry fixture is non-executable test data containing signature strings only.

This `.wsb` template maps a host folder read-only and is intended for inert fixtures and application checks. For live malware work, use a disposable VM with no host folder mapping, no shared clipboard, and no network connection. IronWall observes files and processes in user mode; it does not prevent execution or encryption by a fast moving sample.
