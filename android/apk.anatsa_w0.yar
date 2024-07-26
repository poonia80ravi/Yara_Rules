rule apk_anatsa_w0 {
    meta:
        author = "Thomas Barabosch, Telekom Security"
        version = "20210819"
        description = "matches on dumped, decrypted V/DEX files of Teabot"
        sample = "37be18494cd03ea70a1fdd6270cef6e3"
        source = "https://github.com/telekom-security/malware_analysis/tree/main/flubot"

        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/apk.anatsa"
        malpedia_version = "20210914"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $dex = "dex"
        $vdex = "vdex"
        $s1 = "ERR 404: Unsupported device"
        $s2 = "Opening inject"
        $s3 = "Prevented samsung power off"
        $s4 = "com.huawei.appmarket"
        $s5 = "kill_bot"
        $s6 = "kloger:"
        $s7 = "logged_sms"
        $s8 = "xiaomi_autostart"

    condition:
        ($dex at 0 or $vdex at 0)
        and 6 of ($s*)
}
