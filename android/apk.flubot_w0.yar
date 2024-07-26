rule apk_flubot_w0 {
    meta:
        author = "Thomas Barabosch, Telekom Security"
        version = "20210720"
        description = "matches on dumped, decrypted V/DEX files of Flubot version > 4.2"
        sample = "37be18494cd03ea70a1fdd6270cef6e3"
        source = "https://github.com/telekom-security/malware_analysis/tree/main/flubot"

        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/apk.flubot"
        malpedia_version = "20210914"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $dex = "dex"
        $vdex = "vdex"
        $s1 = "LAYOUT_MANAGER_CONSTRUCTOR_SIGNATURE"
        $s2 = "java/net/HttpURLConnection;"
        $s3 = "java/security/spec/X509EncodedKeySpec;"
        $s4 = "MANUFACTURER"

    condition:
        ($dex at 0 or $vdex at 0)
        and 3 of ($s*)
}
