import "pe"

rule win_industroyer_w1 {
    meta:
        description = "CRASHOVERRIDE v1 Wiper"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = "SYS_BASCON.COM" fullword nocase wide
        $s1 = ".pcmp" fullword nocase wide
        $s2 = ".pcmi" fullword nocase wide
        $s3 = ".pcmt" fullword nocase wide
        $s4 = ".cin" fullword nocase wide
        
    condition:
        pe.exports("Crash") and any of ($s*)
}
