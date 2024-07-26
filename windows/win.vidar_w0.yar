rule win_vidar_w0 {
    meta:
        description = "Yara rule for detecting Vidar stealer"
        author = "Fumik0_"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        malpedia_version = "20190106"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $s1 = { 56 69 64 61 72 }
        $s2 = { 31 42 45 46 30 41 35 37 42 45 31 31 30 46 44 34 36 37 41 }
        
    condition:
        all of them
}
