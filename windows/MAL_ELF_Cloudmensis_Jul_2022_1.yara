rule MAL_ELF_CloudMensis_Jul_2022_1 : cloudmensis client
{
   meta:
        description = "Detect the CloudMensis implant"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/"
        date = "2022-07-24"
        hash1 = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
        hash2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 48 83 ec 18 48 8b 3d [2] 02 00 48 8b 35 [2] 02 00 ff 15 [2] 01 00 48 89 c7 e8 ?? 90 00 00 48 89 c3 48 85 c0 74 15 48 8b 15 [2] 02 00 48 8d 7d e0 48 89 de e8 ?? 90 00 00 eb 0f 0f 57 c0 0f 29 45 e0 48 c7 45 f0 00 00 00 00 48 89 df ff 15 [2] 01 00 48 8b 45 e0 48 8b 4d e8 48 83 f8 0c 74 0c 48 83 f8 0b 75 0a 48 83 c1 10 eb 04 48 83 c1 17 48 8d 41 ff 48 83 f8 3b b8 3c 00 00 00 48 0f 42 c1 48 83 }
        $s2 = { 49 89 fe 48 89 f7 ff 15 [2] 00 00 49 89 c7 48 85 c0 74 1b 49 8b 46 20 48 8b 58 08 4c 89 ff ff 15 [2] 00 00 48 8b 7b 28 48 89 43 28 eb 31 48 8b 35 [2] 01 00 48 8d 3d [2] 01 00 ba 04 00 00 00 ff 15 [2] 00 00 48 89 c7 e8 ?? 2a 00 00 49 8b 4e 20 48 8b 49 08 48 8b 79 28 48 89 41 28 48 8b 1d [2] 00 00 ff d3 4c 89 ff 48 89 d8 48 83 c4 08 }
        $s3 = { 53 48 83 ec 18 49 89 cd 48 89 fb 48 89 d7 ff 15 0c ?? 03 00 49 89 c4 48 8d 7d c0 48 89 1f 48 8b 05 [2] 04 00 48 89 47 08 48 8b 35 [2] 04 00 e8 [2] 02 00 49 89 c7 48 85 c0 0f 84 c8 00 00 00 48 8b 35 [2] 04 00 4c 8b 35 c1 ?? 03 00 4c 89 ff 4c 89 e2 41 ff d6 48 8b 35 [2] 04 00 4c 89 ff 4c 89 ea 41 ff d6 4c 89 e3 4c 8b 25 [2] 04 00 e8 [2] 02 00 4c 89 6d d0 41 89 c5 e8 [2] 02 00 48 8b 35 [2] 04 00 48 8d 15 [2] 03 00 4c 89 e7 44 89 e9 41 89 c0 31 c0 41 ff d6 48 89 c7 e8 [2] 02 00 49 89 c4 48 8b 35 [2] 04 00 4c 89 ff 48 89 c2 41 ff d6 4c 8b 2d 57 ?? 03 00 4c 89 e7 49 89 dc 41 ff d5 48 8b 3d [2] 04 00 e8 [2] 02 00 48 8b 35 [2] 04 00 48 89 c7 48 8b 55 d0 41 ff d6 48 89 c3 48 8b 35 [2] 04 00 4c 89 ff 48 89 c2 41 ff d6 48 89 df 41 ff d5 4c 89 ff ff 15 17 ?? 03 00 48 8b 1d 08 ?? 03 00 4c 89 e7 ff d3 4c 89 ff ff d3 4c 89 f8 48 83 }
        $s4 = { 48 89 d3 83 c6 f6 83 fe 02 0f 87 9c 00 00 00 4c 8d 3d [2] 03 00 41 f6 47 1a 01 0f 84 8a 00 00 00 48 89 df be 09 00 00 00 e8 [2] 02 00 49 89 c6 48 8d 3d [2] 03 00 e8 [2] 02 00 41 f6 47 1a 01 74 5b 4c 8b 3d [2] 03 00 4c 8b 25 [2] 03 00 41 0f b7 fe e8 62 00 00 00 48 8b 35 [2] 03 00 48 8d 15 [2] 03 00 4c 8b 2d [3] 00 4c 89 e7 48 89 c1 31 c0 41 ff d5 48 89 c7 e8 [2] 02 00 49 89 c6 48 8b 35 [2] 03 00 4c 89 ff 48 89 c2 41 ff d5 4c 89 f7 ff 15 [3] 00 48 8d 3d [2] 03 00 e8 [2] 02 00 48 89 d8 48 83 c4 }
   condition:
       uint32(0) == 0xbebafeca and filesize > 300KB and all of ($s*)
}
