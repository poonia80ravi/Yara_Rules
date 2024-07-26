rule win_fickerstealer_w0 {
  meta: 
    author = "Ben Cohen, CyberArk"
    date = "22-02-2021"
    version = "1.0"
    hash = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
    source = "https://github.com/cyberark/malware-research/blob/master/FickerStealer/Ficker_Stealer.yar"
    description = "Yara rule for Ficker Stealer"
    malpedia_rule_date = "20210726"
    malpedia_hash = ""
    malpedia_version = "20210726"
    malpedia_license = "CC BY-NC-SA 4.0"
    malpedia_sharing = "TLP:WHITE"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fickerstealer"
  
  strings:
    //$decryption_pattern = { 89 ?? C1 ?? ?? 31 ?? 89 ?? C1 ?? ?? 31 ?? 8B ?? ?? 89 ?? C1 ?? ?? 31 }
    $c2_const = { 0C 00 0F 0A [0-4] 0B 0A 0B 0A }

    $s1 = "kindmessage"
    $s2 = "SomeNone"
    $s3 = ".Kind"

  condition:
    //$decryption_pattern and
    $c2_const and
    (1 of ($s*)) and
    uint16(0) == 0x5A4D
}
