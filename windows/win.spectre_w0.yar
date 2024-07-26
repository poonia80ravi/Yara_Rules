rule win_spectre_w0 {  
    meta:  
        author = "Yoroi Malware Zlab"  
        description = "Yara Rule for Spectre RAT, versions 2,3,4"  
        last_updated = "2021_10_08"  
        tlp = "white" 
        category = "informational"  

        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spectre"
        malpedia_version = "20211022"
        malpedia_hash = ""
        malpedia_rule_date = "20211022"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:  
        $main = {FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 3D B7 00 00 00 75 06 57 E8 ?? 7? 00 00 E8 }  
        $c2_send_request = {ff 15 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 4f 04 c7 07 01 00 00 00 e8 ?? ?? ?? ?? 8b [0-6] 00 10 00 00 83 f8 08 72 ?? 8b 4? [0-2] 8d 04 45 02 00 00 00 89 4?}  

    condition:  
        all of them and uint16(0) == 0x5A4D  
}
