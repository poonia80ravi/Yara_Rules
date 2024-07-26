rule win_asyncrat_w0 { 
    meta: 
        description = "detect AsyncRat in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash = "1167207bfa1fed44e120dc2c298bd25b7137563fdc9853e8403027b645e52c19"
        hash = "588c77a3907163c3c6de0e59f4805df41001098a428c226f102ed3b74b14b3cc"
        source = "https://github.com/JPCERTCC/MalConfScan/blob/master/yara/rule.yara"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        malpedia_rule_date = "20201006"
        malpedia_hash = ""
        malpedia_version = "20201006"
        malpedia_license = "CC NC-BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    
    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00} $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $s1 = "pastebin" ascii wide nocase
        $s2 = "pong" wide $s3 = "Stub.exe" ascii wide
        
    condition: 
        ($salt and (2 of ($s*) or 1 of ($b*))) or (all of ($b*) and 2 of ($s*))
}

