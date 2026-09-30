# Windows Sandbox test checklist

1. Copy this repository or a built `IronWall-Antivirus.exe` into Windows Sandbox.
2. Install dependencies with `py -m pip install -r requirements.txt`, then start it with `py -m ironwall.main` (or run the EXE).
3. Create a harmless EICAR sample using the official [EICAR procedure](https://www.eicar.org/download-anti-malware-testfile/). Do not download live malware.
4. Use **Scan File** to verify detection of `EICAR-Test-File`, then quarantine and restore it.
5. Enable real-time monitoring after configuring a monitored directory, create the same harmless test sample there, and confirm a security event appears.

Windows Defender may independently detect EICAR first; that is expected.
