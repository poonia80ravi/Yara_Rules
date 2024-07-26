rule RAN_AtomSilo_Dec_2021_1
{
    meta:
        description = "Detect AtomSilo ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-18"
        reference = "Internal Research"
        hash1 = "15ea46c22b2b5e06b4a8f4dd163b3f89975ca606432e0d79315b6513f1e1f550"
        hash2 = "b9022a2da23738066cf3e93478e7126d058e07614401df8558558706400eb43b"
	hash3 = "7a5999c54f4588ff1581d03938b7dcbd874ee871254e2018b98ef911ae6c8dee"
	hash4 = "5f614a8e35bd80a603cf98846c6a44030ad18bed45ac83bd2110d83e8a090de4"
        tlp = "Clear"
        adversary = "AtomSilo"
    strings:
        $s1 = { b0 24 10 3f 01 00 00 00 c0 24 10 3f 01 00 00 00 38 63 1a 3f 01 00 00 00 1c 84 10 3f 01 00 00 00 a0 03 11 3f 01 00 00 00 50 04 11 3f 01 00 00 00 48 fe 19 3f 01 00 00 00 a0 91 12 3f 01 00 00 00 70 1f 10 3f 01 00 00 00 40 20 10 3f 01 00 00 00 80 20 10 3f 01 00 00 00 50 95 12 3f 01 00 00 00 90 24 10 3f 01 00 00 00 10 a1 12 3f 01 00 00 00 a0 a7 12 3f 01 00 00 00 b0 24 10 3f 01 00 00 00 90 24 10 3f 01 00 00 00 90 24 10 3f 01 00 00 00 10 99 12 3f 01 00 00 00 70 96 12 3f 01 00 00 00 d0 9c 12 3f 01 00 00 00 b0 24 10 3f 01 00 00 00 c0 24 10 3f 01 00 00 00 f0 05 11 3f 01 00 00 00 20 fa 10 3f 01 00 00 00 d0 02 11 3f 01 00 00 00 70 02 11 3f 01 00 00 00 c0 08 11 3f 01 00 00 00 60 08 11 3f 01 00 00 00 50 11 11 3f 01 00 00 00 50 14 11 3f 01 00 00 00 c0 07 11 3f 01 00 00 00 d0 f9 10 3f 01 00 00 00 10 04 11 3f 01 00 00 00 40 12 11 3f 01 00 00 00 d0 11 11 3f 01 00 00 00 90 24 10 3f 01 00 00 00 d0 24 10 3f 01 00 00 00 c0 24 10 3f 01 00 00 00 70 2a 10 3f 01 00 00 00 c0 24 10 3f 01 00 00 00 30 92 12 3f 01 00 00 00 50 93 12 3f 01 00 00 00 d0 93 12 3f 01 00 00 00 70 92 12 3f 01 00 00 00 e0 92 12 3f 01 00 00 00 70 0f 11 3f 01 00 00 00 90 24 10 3f 01 00 00 00 00 25 10 3f 01 00 00 00 c0 24 10 3f 01 00 00 00 30 25 10 3f 01 00 00 00 70 fa 10 3f 01 00 00 00 00 ff 19 3f 01 00 00 00 88 91 12 3f 01 00 00 00 a0 03 11 3f 01 00 00 00 50 04 11 3f 01 00 00 00 }
        $s2 = { 48 8d 0d 59 e5 07 00 e9 08 f8 03 00 cc cc cc cc 48 83 ec 28 80 3d 09 33 0c 00 00 75 0c e8 ae 11 02 00 c6 05 fb 32 0c 00 01 66 0f 6f 05 3f 4a 08 00 48 8d 05 e0 41 08 00 45 33 c0 48 89 05 26 33 0c 00 48 8d 0d 27 33 0c 00 f3 0f 7f 05 27 33 0c 00 41 8d 50 02 e8 86 26 02 00 33 c9 48 89 05 25 33 0c 00 89 0d 27 33 0c 00 48 c7 00 01 00 00 00 48 8b 05 11 33 0c 00 48 89 48 08 48 8d 0d fe e4 07 00 48 83 c4 28 e9 89 f7 03 00 cc cc cc cc cc 48 83 ec 28 80 3d 89 32 0c 00 00 }
        $s3 = { 55 53 66 bb d1 27 48 63 da 51 0f 93 c5 41 56 41 51 0f 97 c1 66 87 d9 66 40 0f b6 de 56 4d 0f b7 cd 45 0f b7 cf 41 0f 99 c1 41 52 66 0f 48 f2 49 0f bf ce 40 b6 23 52 41 54 0f 92 c1 66 41 0f ca 4d 8b cb 41 53 9c 40 0f 94 c6 f5 57 48 d3 db 41 8a de 41 b3 ff 50 41 57 66 f7 d0 66 d3 d9 41 55 c0 d5 62 48 b8 00 00 00 00 00 00 00 00 40 0f 96 c6 41 86 db 50 66 44 0f be ca 41 d2 d3 e9 2d 47 0b 00 66 41 8b 18 66 41 0f ba f1 2b f8 41 8a 48 02 41 d2 e9 40 80 fc b2 44 12 cb 49 81 e8 06 }
        $s4 = { 48 63 f8 41 8b 3b 66 41 f7 c0 a5 7b 33 fb c1 c7 03 40 84 f9 f7 df d1 cf 44 84 e0 f9 81 c7 ec 09 cc 10 e9 33 ab 03 00 4d 8b 13 41 fe c9 4d 8b 4b 08 e9 f0 87 06 00 e9 de 6d f6 ff 48 ff c3 f8 41 f7 c7 47 58 66 5e 81 f1 f9 4f a1 63 48 ff c8 e9 3e 75 ff ff e9 2a 7c 07 00 f5 4c 03 c6 e9 da e4 f7 ff 41 8b 10 66 41 0f cb d2 fd 41 c0 fb 69 45 8b 58 04 66 f7 c6 d5 1e 49 81 e8 04 00 00 00 66 c1 f9 47 66 81 f1 99 20 f7 d2 66 41 33 cb 48 f7 d9 41 80 fd 1b 41 f7 d3 48 c1 e9 67 41 0b d3 0f b7 c8 e9 5b c0 f9 ff e9 39 d8 f6 ff 66 44 85 cd 4d 03 c2 e9 3f b6 00 00 ff cb 66 41 3b c3 f5 41 53 41 80 eb 6f 45 0f ac c3 e7 31 1c 24 41 81 db 7b 54 03 47 49 81 fd 54 4b 54 7d 41 5b 48 63 db e9 70 64 fd ff 48 8b 1f 66 41 0f ba f2 b5 f8 8b 4f 08 45 0f bf d3 48 81 c7 0c 00 00 00 4d 0f bf d2 4d 2b d5 e9 89 14 fb ff 8a 4d 10 66 41 81 c1 1d 31 66 45 1b cf 48 81 c5 02 00 00 00 4c 0f a5 d0 e9 d1 a4 fe ff 66 44 0f b6 5c 25 00 44 8a 4d 02 66 d3 d2 48 81 ed 06 00 00 00 0f c0 d6 81 }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and 2 of ($s*) 
}