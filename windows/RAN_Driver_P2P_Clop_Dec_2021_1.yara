rule RAN_Driver_P2P_Clop_Dec_2021_1
{
    meta:
        description = "Detect the driver used by TA505 group for Clop ransomware (x64 version) "
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "e58b80e4738dc03f5aa82d3a40a6d2ace0d7c7cfd651f1dd10df76d43d8c0eb3"
        hash2 = "d98bdf3508763fe0df177ef696f5bf8de7ff7c7dc68bb04a14a95ec28528c3f9"
        hash3 = "6d5de7e73803f09fbb98782c071f1882b5bfb681631801f55bc162efbc0b1d03"
        tlp = "Clear"
        adversary = "TA505"
    strings:
        $s1 = { c7 84 24 a4 00 00 00 f6 00 00 00 8b 4c 24 54 e8 17 fa ff ff 8b 54 24 24 8b 8c 24 a4 00 00 00 e8 a7 fa ff ff 4c 8b 1d b0 49 00 00 4c 89 5c 24 70 c7 84 24 6c 01 00 00 00 00 00 00 eb 11 8b 84 24 6c 01 00 00 83 c0 01 89 84 24 6c 01 00 00 83 bc 24 6c 01 00 00 04 7d 02 eb e3 48 8d 05 1a 69 00 00 48 89 44 24 78 c7 44 24 2c be 00 00 00 8b 44 24 2c 25 a4 00 00 00 8b 4c 24 2c 83 c1 01 99 f7 f9 8b c8 8b 44 24 2c 0f af c1 89 44 24 2c c7 84 24 b8 00 00 00 9d 00 00 00 8b 8c 24 b8 00 00 00 0f af 8c 24 b8 00 00 00 8b 44 24 2c 2b c1 89 44 24 2c c7 84 24 80 00 00 00 f0 3f 03 00 8b 05 1c 59 00 00 89 84 24 84 00 00 00 c7 44 24 6c 67 00 00 00 48 8d 44 24 6c 48 89 44 24 40 48 8b 44 24 40 8b 4c 24 6c 8b 00 23 c1 8b 4c 24 6c 83 c1 01 99 f7 f9 8b c8 8b 44 24 6c 0f af c1 89 44 24 6c 8b 05 dd 58 00 00 89 84 24 88 00 00 00 }
        $s2 = { c7 44 24 44 d5 00 00 00 8b 44 24 44 8b 4c 24 44 23 c8 03 4c 24 44 8b 44 24 44 03 c1 89 44 24 44 48 8b 05 ea 4b 00 00 48 89 44 24 58 c7 84 24 bc 00 00 00 00 00 00 00 eb 11 8b 84 24 bc 00 00 00 83 c0 01 89 84 24 bc 00 00 00 83 bc 24 bc 00 00 00 05 0f 8d 95 00 00 00 c7 44 24 40 8c 00 00 00 }
        $s3 = { 89 44 24 48 c7 44 24 5c ee 00 00 00 8b 4c 24 5c 81 c9 7c 58 00 00 03 4c 24 5c 8b 44 24 5c 2b c1 89 44 24 5c 44 8b 84 24 c0 00 00 00 0f b6 94 24 b8 00 00 00 48 8b 8c 24 b0 00 00 00 ff 15 5b 35 00 00 c7 44 24 60 e4 00 00 00 48 8d 44 24 60 48 89 44 24 68 8b 44 24 60 8b 54 24 60 0b d0 48 8b 44 24 68 8b 4c 24 60 8b 00 23 c1 8b ca 03 c8 8b 44 24 60 2b c1 89 44 24 60 eb 08 c7 44 24 58 01 00 00 00 c7 44 24 70 00 00 00 00 eb 0b 8b 44 24 70 83 c0 01 89 44 24 70 83 7c 24 70 02 0f 8d 91 00 00 00 c7 44 24 78 e0 71 00 00 8b 4c 24 78 e8 29 f1 ff ff c7 44 24 74 91 00 00 00 81 7c 24 74 92 84 00 00 7f 31 c7 44 24 38 a7 28 1b fe 48 8d 44 24 38 48 89 84 24 80 00 00 00 8b 4c 24 38 83 c1 01 }
        $s4 = { c7 44 24 48 7c 00 00 00 8b 4c 24 48 8b 44 24 48 03 c1 89 44 24 54 e9 1f ff ff ff 44 8b 84 24 b0 00 00 00 0f b6 94 24 a8 00 00 00 48 8b 8c 24 a0 00 00 00 ff 15 35 37 00 00 c7 44 24 7c 00 00 00 00 eb 0b 8b 44 24 7c 83 c0 01 89 44 24 7c 83 7c 24 7c 03 7d 34 c7 84 24 88 00 00 00 7b aa 00 00 48 8d 84 24 88 00 00 00 48 89 84 24 80 00 00 00 48 8b 84 24 80 00 00 00 8b 08 8b 84 24 88 00 00 00 2b c1 89 44 24 44 eb ba eb 08 c7 44 24 40 01 00 00 00 c7 44 24 28 80 00 00 00 8b 4c 24 28 8b 44 24 28 2b c1 89 44 24 2c c7 44 24 24 24 00 00 00 8b 44 24 24 8b 4c 24 2c 2b c8 8b 44 24 24 2b c1 89 44 24 24 8b 44 24 }
        $s5 = { 48 81 ec [2] 00 00 41 b8 67 61 54 31 ba 84 0f 00 00 33 c9 ff 15 ?? 4d 00 00 48 89 84 24 ?? 00 00 00 c7 84 24 ?? 00 00 00 00 00 00 00 eb 11 8b 84 24 ?? 00 00 00 83 c0 01 89 84 24 ?? 00 00 00 83 bc 24 ?? 00 00 00 }
        $s6 = { 48 8d 15 [2] 00 00 48 8d 0d [2] 00 00 ff 15 [2] 00 00 85 c0 0f 8d [2] 00 00 }
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and 4 of ($s*) 
}