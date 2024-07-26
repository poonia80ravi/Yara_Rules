rule MAL_SiMayRAT_Mar_2022_2 : rat simayrat
{
   meta:
        description = "Detect a variant of SiMayRAT"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1513811422148538369"
        date = "2022-04-26"
        hash1 = "f1375500194e3ec6d0e045fa9973bb7c01f2e7d8a9ece5764819744bc786cfc1"
        hash2 = "12e20cf17a81cb58d115a7cc76f8416ace6bd261381e12a7128f945084102588"
        hash3 = "8ff9a7248f52119053c9535df111eba4f0289cdb0f78b1cb6a0471ccee5c046c"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 83 bd [2] ff ff 10 8d 85 [2] ff ff 8b b5 [2] ff ff 8d 4d ?? 0f 43 85 [2] ff ff [3] 45 }
        $s2 = { 83 7d 20 08 8d 4d 0c 8d 45 ?? 0f 43 4d 0c 83 7d ?? 08 51 0f 43 45 ?? 68 90 ?? 45 00 50 ff 15 d0 ?? 45 00 83 c4 0c 8d 45 ?? 83 7d ?? 08 0f 43 45 ?? 50 ff 15 8c ?? 45 00 8b }
        $s3 = { 8b 7d 0c 33 f6 56 ff 77 08 ff 77 0c ff 75 08 ff 15 84 ?? 45 00 85 c0 75 16 ff 15 18 ?? 45 00 50 e8 04 18 00 00 59 e8 34 18 00 00 8b 30 eb 2d 3b 47 0c 76 25 40 8b cf 50 e8 c2 c6 ff ff 85 c0 74 04 8b f0 eb 17 56 ff 77 08 ff 77 0c ff 75 08 ff 15 84 ?? 45 00 85 c0 74 c0 }
        $s4 = { 85 c0 75 05 33 c0 40 eb 30 83 c0 40 6a 3a 66 89 45 f4 58 66 89 45 f6 6a 5c 58 66 89 45 f8 33 c0 66 89 45 fa 8d 45 f4 50 ff 15 80 ?? 45 00 85 c0 74 05 83 f8 01 75 cd 33 c0 8b 4d fc 33 cd e8 }
        $s5 = { 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 65 66 65 6e 64 65 72 00 00 00 6c 61 6c 61 6c 61 31 32 33 40 00 00 74 65 6c 6e 65 74 2f }
     condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
