rule apk_rana_w0 {

    meta:
        author = "ReversingLabs"
        description = "Detects Rana Android Malware Resource strings"
        reference = "https://blog.reversinglabs.com/blog/rana-android-malware"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/apk.rana"
        malpedia_version = "20201208"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $res1 = "res/raw/cng.cn" fullword wide ascii
        $res2 = "res/raw/att.cn" fullword wide ascii
        $res3 = "res/raw/odr.od" fullword wide ascii

    condition:
        filesize < 1MB and any of them
}
