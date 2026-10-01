# Run IronWall in Windows Sandbox

## 1. Prepare the host

Create:

```text
C:\IronWallSandbox
```

Copy these files into it:

- `IronWall-Antivirus.exe`
- `IronWall-Isolated.wsb`
- `create_test_samples.ps1`

## 2. Start Sandbox

Double-click:

```text
IronWall-Isolated.wsb
```

Inside Sandbox, open the **IronWall** folder, copy `IronWall-Antivirus.exe` to the Desktop, and run it.

## 3. Create safe test files

Open PowerShell inside Sandbox and run:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\IronWall\create_test_samples.ps1
```

The samples are created in:

```text
Downloads\IronWall-Test-Samples
```

## 4. Test IronWall

- Scan the `IronWall-Test-Samples` folder.
- Confirm detections appear.
- Try **Quarantine** and **Restore**.
- Add the test folder to real-time monitoring and copy a sample into it.

Windows Defender may remove EICAR before IronWall sees it. That is normal. Keep Defender enabled and do not use live malware for this test.
