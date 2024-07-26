rule win_hive_w0 {
    meta:
        author = "rivitna"
        family = "ransomware.hive"
        description = "Hive v3 ransomware Windows/Linux/FreeBSD payload"
        source = "https://github.com/rivitna/Malware/blob/main/Hive/Hive.yar"
        severity = 10
        score = 100
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hive"
        malpedia_rule_date = "20211222"
        malpedia_hash = ""
        malpedia_version = "20211222"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $h0 = { B? 03 52 DA 8D [6-12] 69 ?? 00 70 0E 00 [14-20]
                8D ?? 00 90 01 00 }
        $h1 = { B? 37 48 60 80 [4-12] 69 ?? 00 F4 0F 00 [2-10]
                8D ?? 00 0C 00 00 }
        $h2 = { B? 3E 0A D7 A3 [2-6] C1 E? ( 0F | 2F 4?)
                69 ?? 00 90 01 00 }

        $x0 = { C6 84 24 ?? 00 00 00 FF [0-14] 89 ?? 24 ?? 00 00 00 [0-6]
                89 ?? 24 ?? 0? 00 00 [0-20] C6 84 24 ?? 0? 00 00 34 }
        $x1 = { C6 44 24 ?? FF [0-14] 89 ?? 24 ?? [0-6] 89 ?? 24 ?? [0-12]
                C6 84 24 ?? 00 00 00 34 }

    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            (2 of ($h*)) or (1 of ($x*))
        )
}
