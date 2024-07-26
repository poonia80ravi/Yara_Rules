rule win_juicy_potato_w0 {
    meta:
        author = "SpiderLabs"
        source = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/copy-paste-threat-actor-in-the-asia-pacific-region/"
        group = "copy_paste"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.juicy_potato"
        malpedia_version = "20200624"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $str1 = "JuicyPotato" nocase wide ascii
        $str2 = "4991d34b-80a1-4291-83b6-3328366b9097" nocase wide ascii
        $str3 = "JuicyPotato.pdb" nocase wide ascii
        $str4 = "Waiting for auth" nocase wide ascii
    condition:        
        (uint16(0) == 0x5A4D) and 3 of ($str*) and filesize < 500KB
}
