rule win_triton_w1 {
    meta:
        author = "DHS/NCCIC/ICS-CERT"
        description = "Matches the known samples of the HatMan malware."
        info = "original ruleset condensed into one rule."
        source = ""
        malpedia_rule_date = "20210727"
        malpedia_hash = ""
        malpedia_version = "20210727"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.triton"
    strings:
        $nullsub = { ff ff 60 38 02 00 00 44 20 00 80 4e }
        $preset = { 80 00 40 3c 00 00 62 80 40 00 80 3c 40 20 03 7c
                    ?? ?? 82 40 04 00 62 80 60 00 80 3c 40 20 03 7c
                    ?? ?? 82 40 ?? ?? 42 38                         }
        $div1 = { 9a 78 56 00 }
        $div2 = { 34 12 00 00 }
        $memcpy_be = { 7c a9 03 a6 38 84 ff ff 38 63 ff ff 8c a4 00 01
                       9c a3 00 01 42 00 ff f8 4e 80 00 20             }
        $memcpy_le = { a6 03 a9 7c ff ff 84 38 ff ff 63 38 01 00 a4 8c
                       01 00 a3 9c f8 ff 00 42 20 00 80 4e             }
        $oaddr_be = { 3c 60 00 03 60 63 96 f4 4e 80 00 20 }
        $oaddr_le = { 03 00 60 3c f4 96 63 60 20 00 80 4e }
        $loadoff_be = { 80 60 00 04 48 00 ?? ?? 70 60 ff ff 28 00 00 00
                        40 82 ?? ?? 28 03 00 00 41 82 ?? ??             }
        $loadoff_le = { 04 00 60 80 ?? ?? 00 48 ff ff 60 70 00 00 00 28
                        ?? ?? 82 40 00 00 03 28 ?? ?? 82 41             }
        $mfmsr_be = { 7c 63 00 a6 }
        $mfmsr_le = { a6 00 63 7c }
        $mtmsr_be = { 7c 63 01 24 }
        $mtmsr_le = { 24 01 63 7c }
        $ocode_be = { 3c 00 00 03 60 00 a0 b0 7c 09 03 a6 4e 80 04 20 }
        $ocode_le = { 03 00 00 3c b0 a0 00 60 a6 03 09 7c 20 04 80 4e }
    condition:
        ((filesize < 350KB) and $nullsub and $preset and $div1 and $div2)
        or ((filesize < 350KB) and ($memcpy_be or $memcpy_le) and ($oaddr_be or $oaddr_le) and ($loadoff_be or $loadoff_le) and not (filesize < 350KB) and ($memcpy_be or $memcpy_le) and ($ocode_be or $ocode_le) and (($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le))) 
        or ((filesize < 350KB) and ($memcpy_be or $memcpy_le) and ($ocode_be or $ocode_le) and (($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le)) and not (filesize < 350KB) and ($memcpy_be or $memcpy_le) and ($oaddr_be or $oaddr_le) and ($loadoff_be or $loadoff_le)) 
        or ((filesize < 350KB) and ($memcpy_be or $memcpy_le) and ($oaddr_be or $oaddr_le) and ($loadoff_be or $loadoff_le) and (filesize < 350KB) and ($memcpy_be or $memcpy_le) and ($ocode_be or $ocode_le) and (($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le)) and $div1 and $div2)
}
