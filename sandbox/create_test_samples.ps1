$ErrorActionPreference = "Stop"
$Destination = Join-Path $env:USERPROFILE "Downloads\IronWall-Test-Samples"
New-Item -ItemType Directory -Force -Path $Destination | Out-Null

# Standard harmless EICAR test content. Defender may remove it before IronWall scans it.
$EicarA = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-'
$EicarB = 'ANTIVIRUS-TEST-FILE!$H+H*'
$EicarPath = Join-Path $Destination "eicar.com"
try {
    [IO.File]::WriteAllText($EicarPath, $EicarA + $EicarB, [Text.Encoding]::ASCII)
    Write-Host "Created $EicarPath"
} catch {
    Write-Warning "EICAR could not be written, usually because Defender intercepted it: $($_.Exception.Message)"
}

# Non-executable fixture containing multiple WannaCry indicators. It is safe test data,
# begins with MZ only so the YARA rule exercises its PE-file guard, and contains no code.
$FixturePath = Join-Path $Destination "harmless-wannacry-signature-fixture.bin"
$Fixture = [Text.Encoding]::ASCII.GetBytes(
    "MZ`0SAFE TEST ONLY`0@WanaDecryptor@.exe`0.WNCRY`0Ooops, your files have been encrypted!`0"
)
[IO.File]::WriteAllBytes($FixturePath, $Fixture)
Write-Host "Created $FixturePath"
Write-Host "These are harmless detection fixtures. No live malware was downloaded or created."
