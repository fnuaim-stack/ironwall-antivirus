$ErrorActionPreference = "Stop"
python -m PyInstaller --noconfirm --windowed --name IronWall-Antivirus --add-data "rules;rules" --collect-all PySide6 ironwall/main.py
Write-Host "Built dist\IronWall-Antivirus\IronWall-Antivirus.exe"
