rule MAL_Allcome_Feb_2022_1
{
   meta:
        description = "Detect the Allcome clipper"
        author = "Arkbird_SOLG"
        reference = "https://www.gdatasoftware.com/blog/2022/02/37239-allcome-clipbanker-is-a-newcomer-in-malware-underground-forums"
        date = "2022-02-16"
        hash1 = "b742bd51b1727c6252b4abd2373aac0e477a96d89ecd5ab8afc16192677f6210"
        hash2 = "f294dbf9e74d865423a0bb1299678df8c73a67f2e530bce89c1535046702adae"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = "https://steamcommunity.com/tradeoffer" ascii
        $s2 = { 73 63 68 74 61 73 6b 73 00 00 00 00 6f 70 65 6e 00 00 00 00 2f 43 72 65 61 74 65 20 2f 74 6e 20 4e 76 54 6d 52 65 70 5f 43 72 61 73 68 52 65 70 6f 72 74 33 5f 7b [4-16] 7d 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 74 72 20 25 73 00 00 25 73 25 73 }
        $s3 = { 8b 44 24 18 68 [3] 00 ff 74 06 [5-6] 00 83 c4 08 85 c0 74 ?? 8b 44 24 18 68 [3] 00 ff 74 06 08 [4-5] 00 83 c4 08 85 c0 75 02 b3 01 47 83 c6 10 3b 7c 24 1c 72 ?? 8b 44 24 18 85 c0 74 07 50 ff 15 [3] 00 80 fb 01 0f 84 ?? 01 00 00 }
        $s4 = { 6a 00 e8 84 fd ff ff 6a 00 6a 00 6a 00 6a 01 68 [3] 00 8b f0 ff 15 [3] 00 8b d8 85 db 0f 84 ?? 02 00 00 6a 00 6a 00 6a 00 6a 00 56 53 ff 15 [3] 00 8b f0 85 f6 0f 84 ?? 02 00 00 8b 3d ?? 41 ?? 00 0f 1f 44 00 00 8d 44 24 1c 50 68 00 04 00 00 8d 84 24 38 02 00 00 50 56 ff d7 83 7c 24 1c 00 75 e4 56 8b 35 [3] 00 ff d6 53 ff d6 80 bc 24 30 02 00 00 2d 0f 84 ?? 01 00 00 6a 04 e8 ?? 0c 00 00 }
        $s5 = { 8d 44 24 20 50 6a 00 6a 00 6a 1c 6a 00 ff 15 [3] 00 85 c0 0f 88 c1 00 00 00 68 [3] 00 8d 44 24 24 50 68 [3] 00 68 04 01 00 00 50 e8 ?? fd ff ff 83 c4 14 85 c0 0f 84 9c 00 00 00 6a 00 8d 44 24 24 50 ff 15 1c 40 ?? 00 8b 35 18 40 ?? 00 8d 44 24 20 6a 02 50 ff d6 68 [3] 00 8d 44 24 24 50 68 [3] 00 68 04 01 00 00 50 e8 ?? fd ff ff 83 c4 14 85 c0 74 5f 6a 00 8d 44 24 24 50 8d 84 24 30 01 00 00 50 ff 15 14 40 ?? 00 6a 02 8d 44 24 24 50 ff d6 8d 44 24 20 50 68 [3] 00 8d 84 24 38 02 00 00 68 04 01 00 00 50 e8 [2] ff ff 83 c4 10 85 c0 74 1e 6a 00 6a 00 8d 84 } 
    condition:
        uint16(0) == 0x5A4D and filesize > 10KB and 4 of ($s*) 
}
