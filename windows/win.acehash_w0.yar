rule win_acehash_w0 {
    meta:
        author = "Bundesamt fuer Verfassungsschutz"
        source = "https://www.verfassungsschutz.de/download/anlage-2019-12-bfv-cyber-brief-2019-01.txt"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acehash"
        malpedia_version = "20191207"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $b1 = { 0F B7 ?? 16 [0-1] (81 E? | 25) 00 20 [0-2] [8] 8B ?? 50 41 B9 40 00 00 00 41 B8 00 10 00 00 }
        $b2 = { 8B 40 28 [5-8] 48 03 C8 48 8B C1 [5-8] 48 89 41 28 }
        $b3 = { 48 6B ?? 28 [5-8] 8B ?? ?? 10 [5-8] 48 6B ?? 28 [5-8] 8B ?? ?? 14 }
        $b4 = { 83 B? 90 00 00 00 00 0F 84 [9-12] 83 B? 94 00 00 00 00 0F 84 }
        $b5 = { (45 | 4D) (31 | 33) C0 BA 01 00 00 00 [10-16] FF 5? 28 [0-1] (84 | 85) C0 }
    condition:
        (4 of ($b*))
}
