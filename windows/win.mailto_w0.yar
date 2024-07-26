rule win_mailto_w0 { 
    meta: 
        copyright = "(c) 2020 Crowdstrike Inc." 
        author = "Crowdstrike"
        description = "Detects the Netwalker ransomware" 
        reports = "CSIT-20081" 
        source = "https://go.crowdstrike.com/rs/281-OBQ-266/images/ReportCSIT-20081e.pdf"
        version = "202004281747" 
        last_modified = "2020-04-28" 
        malware_family = "Netwalker" 
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mailto"
        malpedia_rule_date = "20210224"
        malpedia_hash = ""
        malpedia_version = "20210224"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $salsaconst = "expand 32-byte kexpand 16-byte k" 
        $ins_getapi = {55 8b ec a1 ?? ?? ?? ?? 5d c3} 
        $ins_crc32 = {25 20 83 b8 ed 33 d0} 
        $ins_push1137 = {68 39 05 00 00 68 69 7a 00 00} 
        $ins_rc4 = {8b 45 ( e? | f? ) 83 c0 01 33 d2 b9 00 01 00 00 f7 f1 89 55} 
        $in_c25519 = {6a 00 68 41 db 01 00} 
    condition: 
        3 of them
}
