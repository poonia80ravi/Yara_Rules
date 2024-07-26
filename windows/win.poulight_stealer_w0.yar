rule win_poulight_stealer_w0 {
    meta:
        description = "Poullight stealer"
        author = "James_inthe_box"
        reference = "https://app.any.run/tasks/d9e4933b-3229-4cb4-84e6-c45a336b15be/"
        date = "2020/03"
        maltype = "Stealer"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poulight_stealer"
        malpedia_version = "20200325"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
        
    strings:
        $string1 = "[LOGS]" wide
        $string2 = "Org.BouncyCastle.Crypto.Prng" ascii
        $string3 = "lookupPowX2" ascii

    condition:
            uint16(0) == 0x5A4D
        and 
            all of ($string*)
        and 
            filesize < 400KB
}
