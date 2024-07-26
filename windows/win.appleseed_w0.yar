rule win_appleseed_w0 {
    meta:
        author = "KrCERT/CC Profound Analysis Team"
        date = "2020-12-4"
        info = "Operation MUZABI"
        hash = "43cc6d190238e851d33066cbe9be9ac8"
        hash = "fd10bd6013aabadbcb9edb8a23ba7331"
        hash = "16231e2e8991c60a42f293e0c33ff801"
        hash = "89fff6645013008cda57f88639b92990"
        hash = "030e2f992cbc4e61f0d5c994779caf3b"
        hash = "3620c22671641fbf32cf496b118b85f6"
        hash = "4876fc88c361743a1220a7b161f8f06f"
        hash = "94b8a0e4356d0202dc61046e3d8bdfe0"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.appleseed"
        malpedia_rule_date = "20201015"
        malpedia_version = "20201015"
        malpedia_license = "CC NC-BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $appleseed_str1 = {0f 8? ?? (00|01) 00 00 [0-1] 83 f? 20 0f 8? (01|00) 00 00}
        $appleseed_str2 = {88 45 [0-15] 0f b6 44 ?? 01}
        $appleseed_str3 = {83 f? 10 [0-5] 83 e? 10}
        $appleseed_key1 = {89 04 ?9 [0-6] ff 34 ?? e8 [10-16] 89 0c 98 8b ?? 0c [0-3] ff 34 98}
        $appleseed_key2 = {83 f? 10 [0-10] 32 4c 05 ?? ?? 88 4c ?? 0f}
        $appleseed_key3 = {89 04 ?9 49 83 ?? 04 48 ?? ?? 10 8b 0c a8 e8 [0-10] 48 8b ?? ?8}
        $seed_str1 = {44 0f b6 44 3d c0 45 32 c7 44 32 45 d4}
        $seed_str2 = {0f b6 44 3? ?? [0-25] 83 c4 0c}
        $seed_str3 = {32 45 c? ?? ?? ?? 32 45 e?}

    condition: 
            uint16(0) == 0x5a4d
        and
            filesize < 400KB
        and
            (2 of ($appleseed_str*))
        and
            (1 of ($seed_str*))
        and
            (1 of ($appleseed_key*))
}
