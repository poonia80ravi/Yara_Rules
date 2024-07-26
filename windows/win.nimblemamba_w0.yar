rule win_nimblemamba_w0 { 
    meta: 
        description = "Detects .NET written NimbleMamba malware used by TA402/Molereats" 
        author = "Proofpoint Threat Research" 
        disclaimer = "Yara signature created for hunting purposes - not quality controlled within enterprise environment" 
        source = "https://www.proofpoint.com/us/blog/threat-insight/ugg-boots-4-sale-tale-palestinian-aligned-espionage"
        hash1 = "430c12393a1714e3f5087e1338a3e3846ab62b18d816cc4916749a935f8dab44" 
        hash2 = "c61fcd8bed15414529959e8b5484b2c559ac597143c1775b1cec7d493a40369d" 
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimblemamba"
        malpedia_rule_date = "20220209"
        malpedia_hash = ""
        malpedia_version = "20220209"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $dotnet = "#Strings" ascii   
        $dropbox = "dropboxapi.com" ascii wide 
        $justpaste = "justpaste.it" wide 
  
        $ip_1 = "api.ipstack.com" wide 
        $ip_2 = "myexternalip.com" wide 
        $ip_3 = "ip-api.com" wide 
        $ip_4 = "api.ipify.com" wide 

        $vm_1 = "VMware|VIRTUAL|A M I|Xen" wide 
        $vm_2 = "Microsoft|VMWare|Virtual" wide 
    condition: 
        uint16be(0) == 0x4D5A
        and $dotnet
        and $dropbox
        and $justpaste
        and any of ($ip_*)
        and any of ($vm_*) 
} 
