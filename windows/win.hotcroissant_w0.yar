rule win_hotcroissant_w0 {
    meta:
        author = "VMware CarbonBlack TAU"
        date = "2020-Mar-25"
        validity = 10
        severity = 10
        TID = "T1140, T1082, T1033, T1005, T1113, T1094, T1024, T1132, T1065"
        description = "Lazarus HotCroissant backdoor"
        link = "https://www.us-cert.gov/ncas/analysis-reports/ar20-045d"
        rule_version = 1
        yara_version = "3.11.0"
        confidence = "Prod"
        priority = "Medium"
        tlp = "White"
        hash = "8ee7da59f68c691c9eca1ac70ff03155ed07808c7a66dee49886b51a59e00085"
        hash = "7ec13c5258e4b3455f2e8af1c55ac74de6195b837235b58bc32f95dd6f25370c"

        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hotcroissant"
        malpedia_version = "20200421"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        // Crypto keys
        $b1 = { 8b d6 b8 00 [1-6] 17 [1-6] 29 70 49 02 }

        // Crypto algorithm
        $b2 = { 8A 1C 3E 32 DA 32 D8 32 D9 88 1C 3E 8A D8 32 D9 22 DA 8B 55 FC 8D 3C D5 00 00 00 00 33 FA 81 E7 F8 07 00 00 C1 E7 14 C1 EA 08 0B D7 8D 3C 00 33 F8 22 C8 C1 E7 04 33 F8 32 CB 8B D8 83 E7 80 C1 E3 07 33 FB C1 E7 11 C1 E8 08 }

    condition:
        uint16(0) == 0x5A4D and 
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 200KB and
        any of ($b*)
}
