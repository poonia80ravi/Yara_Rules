rule win_juicy_potato_w1 {
    meta:
        author = "SpiderLabs"
        source = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/copy-paste-threat-actor-in-the-asia-pacific-region/"
        group = "copy_paste"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.juicy_potato"
        malpedia_version = "20200624"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $str1 = "Potato.dll" nocase wide ascii
        $str2 = "VirusDeleted" nocase wide ascii
        $str3 = "Page404r" nocase wide ascii
    condition:        
        (uint16(0) == 0x5A4D) and all of them and filesize < 200KB
}
