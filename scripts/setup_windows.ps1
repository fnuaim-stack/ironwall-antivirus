param(
    [switch]$Launch
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepositoryRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python Launcher was not found. Install Python 3.11 or newer from python.org."
}

py -3 -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11 or newer is required'"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.11 or newer is required."
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create the virtual environment." }
}

$Python = Join-Path $RepositoryRoot ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Could not upgrade pip." }
& $Python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Could not install IronWall dependencies." }

& $Python -m pip install -r requirements-yara.txt
if ($LASTEXITCODE -ne 0) {
    Write-Warning "yara-python could not be installed. Hash, heuristic, and PE scanning remain available."
}

Write-Host "IronWall is ready. Run: .\.venv\Scripts\python.exe -m ironwall.main"
if ($Launch) {
    & $Python -m ironwall.main
}
