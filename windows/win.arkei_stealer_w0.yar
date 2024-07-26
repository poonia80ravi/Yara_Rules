rule win_arkei_stealer_w0 {
    meta:
        author = "Fumik0_"
        description = "Arkei Stealer"
        Date = "2018/07/10"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arkei_stealer"
        malpedia_version = "20181023"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
 
    strings:
        $s1 = "Arkei" wide ascii
        $s2 = "/server/gate" wide ascii
        $s3 = "/server/grubConfig" wide ascii
        $s4 = "\\files\\" wide ascii
        $s5 = "SQLite" wide ascii
 
    condition:
        all of ($s*)   
}
