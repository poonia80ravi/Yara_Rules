rule elf_bpfdoor_w0 {
    meta:
        description = "Detects unknown Linux implants (uploads from KR and MO)"
        author = "Florian Roth"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-05"
        score = 90
        hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
        hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
        hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
        hash4 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
        hash5 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
        hash6 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
        hash7 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
        hash8 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
        hash9 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
        hash10 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
        version = "1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bpfdoor"
        malpedia_rule_date = "20220509"
        malpedia_hash = ""
        malpedia_version = "20220509"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "[-] Connect failed." ascii fullword
        $s2 = "export MYSQL_HISTFILE=" ascii fullword
        $s3 = "udpcmd" ascii fullword
        $s4 = "getshell" ascii fullword

        $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
        $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
        $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
        $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }
    condition:
        uint16(0) == 0x457f and
        filesize < 80KB and 2 of them or 5 of them
}
