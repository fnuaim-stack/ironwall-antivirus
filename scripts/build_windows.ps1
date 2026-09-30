$ErrorActionPreference = "Stop"
python -m PyInstaller --noconfirm --clean IronWall-Antivirus.spec
& ".\dist\IronWall-Antivirus.exe" --smoke-test
if ($LASTEXITCODE -ne 0) { throw "Packaged application smoke test failed" }
Write-Host "Built dist\IronWall-Antivirus.exe"
