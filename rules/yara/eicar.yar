rule IronWall_EICAR_Test
{
  meta:
    description = "Harmless EICAR antivirus test pattern"
    severity = "Test/High"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $eicar
}
