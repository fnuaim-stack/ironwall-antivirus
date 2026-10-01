# Windows Sandbox test checklist

1. Copy this repository or a built `IronWall-Antivirus.exe` into Windows Sandbox.
2. Install dependencies with `py -m pip install -r requirements.txt`, then start it with `py -m ironwall.main` (or run the EXE).
3. Create a harmless EICAR sample using the official [EICAR procedure](https://www.eicar.org/download-anti-malware-testfile/). Do not download live malware. A controlled PowerShell method is shown below.
4. Use **Scan File** to verify detection of `EICAR-Test-File`, then quarantine and restore it.
5. Enable real-time monitoring after configuring a monitored directory, create the same harmless test sample there, and confirm a security event appears.
6. Run Quick Scan and verify its totals and Security Events entries.

```powershell
$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-'
$b = 'ANTIVIRUS-TEST-FILE!$H+H*'
[IO.File]::WriteAllText("$env:USERPROFILE\Downloads\eicar.com", $a + $b, [Text.Encoding]::ASCII)
```

Windows Defender may independently detect EICAR first; that is expected.
