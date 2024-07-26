rule win_fatal_rat_w0 {
    meta: 
        author = "AT&T Alien Labs" 
        description = "Detects FatalRAT, unpacked malware." 
        type = "malware" 
        sha256 = "ec0dcfe2d8380a4bafadb3ed73b546cbf73ef78f893e32202042a5818b67ce56" 
        reference = "https://cybersecurity.att.com/blogs/labs-research/new-sophisticated-rat-in-town-fatalrat-analysis"
        copyright = "Alienvault Inc. 2021" 
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fatal_rat"
        malpedia_rule_date = "20210820"
        malpedia_version = "20210820"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $decrypt_func = {EC 0F B6 45 10 99 B9 AB 05 00 00 56 F7 F9 8B 75 0C 80 C2 3D 85 F6 76 0F 8B 45 08 8A 08 32 CA 02 CA 88 08 40 4E 75 F4 5E 5D C3} 
        $s1 = "SVP7-Thread running..." 
        $s2 = "nw_elf.dll" 
    condition: 
        uint16(0) == 0x5a4d and all of them
}
