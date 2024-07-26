rule win_korlia_w1 { 
    meta: 
        author = "pinksawtooth"
        source = "https://github.com/nao-sec/yara_rules/blob/master/Malware/bisonal.yar"
        reference = "https://www.paloaltonetworks.jp/company/in-the-news/2018/unit42-bisonal-malware-used-attacks-russia-south-korea"
        description = "rule to detect korlia/bisonal"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.korlia"
        malpedia_rule_date = "20210204"
        malpedia_hash = ""
        malpedia_version = "20210204"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $s1 = "akspbu.txt" ascii wide 
        $s2 = "ks8d" ascii wide 
        $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322" ascii wide 
        /* bisonal_decode_jsac */ 
        $decode = { bb bf 58 00 00 [0-2] 8d 0c 40 c1 e1 04 2b c8 8d 0c 49 8d 0c 89 8d 0c c9 8d 04 48 83 c9 ff } 
    condition: 
            uint16(0) == 0x5A4D 
        and
            (all of ($s*) or $decode) 
}
