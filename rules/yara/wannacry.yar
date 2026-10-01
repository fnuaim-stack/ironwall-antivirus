rule IronWall_Ransomware_WannaCry
{
    meta:
        author = "IronWall Antivirus"
        description = "Conservative static indicators associated with WannaCry ransomware"
        threat_name = "Ransom.Win32.WannaCry"
        severity = "Critical"
        reference = "https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_WannaCry.yar"
        reference_hash_rule = "https://github.com/Neo23x0/signature-base/blob/master/yara/crime_wannacry.yar"

    strings:
        $wc_decryptor = "@WanaDecryptor@.exe" ascii wide fullword
        $wc_extension = ".WNCRY" ascii wide
        $wc_ransom_note = "Ooops, your files have been encrypted!" ascii wide nocase
        $wc_bitcoin = "%d worth of bitcoin" ascii fullword
        $wc_batch = "%d%d.bat" ascii fullword
        $wc_task = "tasksche.exe" ascii wide fullword
        $wc_payment = "Please check your payment status" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and 3 of ($wc_*)
}
