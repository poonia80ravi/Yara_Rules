rule win_mailto_w1 { 
    meta: 
        copyright = "(c) 2020 Crowdstrike Inc." 
        author = "Crowdstrike"
        description = "Detects the Netwalker ransomware" 
        reports = "CSIT-20081" 
        source = "https://go.crowdstrike.com/rs/281-OBQ-266/images/ReportCSIT-20081e.pdf"
        version = "202004281748" 
        last_modified = "2020-04-28" 
        malware_family = "Netwalker" 
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mailto"
        malpedia_rule_date = "20210224"
        malpedia_hash = ""
        malpedia_version = "20210224"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $ = "namesz" fullword 
        $ = "crmask" fullword 
        $ = "idsz" fullword 
        $ = "lend" fullword 
        $ = "lfile" fullword 
        $ = "mpk" fullword 
        $ = "namesz" fullword 
        $ = "pspath" fullword 
        $ = "rwsz" fullword 
        $ = "spsz" fullword 
        $ = "svcwait" fullword 
        $ = "unlocker" fullword 
        $ = "onion1" fullword 
    condition: 10 of them
}

