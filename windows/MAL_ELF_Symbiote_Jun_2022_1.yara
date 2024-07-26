rule MAL_ELF_Symbiote_Jun_2022_1 : symbiote backdoor
{
   meta:
        description = "Detect the Symbiote backdoor that targets the financial sector in Latin America"
        author = "Arkbird_SOLG"
        reference = "https://www.intezer.com/blog/research/new-linux-threat-symbiote/"
        date = "2022-06-10"
        hash1 = "a0cd554c35dee3fed3d1607dc18debd1296faaee29b5bd77ff83ab6956a6f9d6"
        hash2 = "ec67bbdf55d3679fca72d3c814186ff4646dd779a862999c82c6faa8e6615180"
        hash3 = "f55af21f69a183fb8550ac60f392b05df14aa01d7ffe9f28bc48a118dc110b4c"
        tlp = "Clear"
        adversary = "-"
   strings: 
        $s1 = { 48 8b 05 [2] 00 00 48 89 45 f0 48 8d 45 f0 ba 07 00 00 00 48 89 c6 48 8d 3d [2] 00 00 e8 [2] ff ff 48 89 c6 48 c7 c7 ff ff ff ff e8 [2] ff ff 48 89 05 [2] 20 00 48 c7 45 f8 00 00 00 00 48 8b 45 e8 48 89 c7 e8 60 01 00 00 85 c0 74 50 eb 14 48 8b 45 f8 48 83 c0 13 48 89 c7 e8 ce 02 00 00 85 c0 75 1d 48 8b 15 [2] 20 00 48 8b 45 e8 48 89 c7 ff d2 48 89 45 f8 48 83 7d f8 }
        $s2 = { 48 83 ec 48 89 7d cc 48 89 75 c0 48 89 55 b8 48 c7 45 e0 ff ff ff ff 48 8b 05 [2] 20 00 48 85 c0 75 39 c7 45 d0 25 b3 9b 51 c6 45 d4 00 48 8d 45 d0 ba 04 00 00 00 48 89 c6 48 8d 3d [2] 00 00 e8 [2] ff ff 48 89 c6 48 c7 c7 ff ff ff ff e8 [2] ff ff 48 89 05 [2] 20 00 48 8b 05 [2] 20 00 48 85 c0 0f 84 84 00 00 00 48 8b 1d [2] 20 00 48 8b 55 b8 48 8b 4d c0 8b 45 cc 48 89 ce 89 c7 ff d3 48 89 45 e0 48 83 7d e0 00 7e 60 e8 [2] ff ff 8b 00 85 c0 75 55 8b 05 [2] 20 00 85 c0 75 10 b8 00 00 00 00 e8 16 02 00 00 89 05 [2] 20 00 8b 05 [2] 20 00 83 f8 02 75 30 e8 [2] ff ff 8b 00 89 45 ec 48 8b 5d c0 48 8b 55 b8 8b 45 cc 48 8d 0d [2] 20 00 48 89 de 89 c7 e8 48 03 00 00 e8 [2] ff ff 8b 55 ec 89 10 48 8b 45 e0 48 83 c4 48 }
        $s3 = { 48 83 ec 58 48 89 7d b8 48 89 75 b0 48 89 55 a8 48 8b 05 [2] 20 00 48 85 c0 75 3f c7 45 c0 32 ae 9f 56 66 c7 45 c4 e3 49 c6 45 c6 00 48 8d 45 c0 ba 06 00 00 00 48 89 c6 48 8d 3d [2] 00 00 e8 [2] ff ff 48 89 c6 48 c7 c7 ff ff ff ff e8 [2] ff ff 48 89 05 [2] 20 00 c7 45 d0 1b 92 a5 61 c7 45 d4 c7 6d a4 f3 c7 45 d8 9a 03 69 d2 c7 45 dc 57 10 2c 30 c7 45 e0 f9 77 b0 91 c7 45 e4 4b 77 08 00 48 8d 45 d0 ba 17 00 00 00 48 89 c6 48 8d 3d [2] 00 00 e8 [2] ff ff 48 89 c7 e8 [2] ff ff 48 89 45 e8 48 83 7d e8 00 74 19 48 8b 55 a8 48 8b 4d b0 48 8b 45 b8 48 89 ce 48 89 c7 e8 ?? fc ff ff eb 1b 48 8b 1d [2] 20 00 48 8b 55 a8 48 8b 4d b0 48 8b 45 b8 48 89 ce 48 89 c7 ff d3 48 83 }
        $s4 = { 4c 8b 25 [2] 20 00 c7 45 ?? 72 a5 86 10 66 c7 45 ?? e6 26 c6 45 ?? 00 48 8d 45 ?? ba 06 00 00 00 48 89 c6 48 8d 3d [2] 00 00 e8 [2] ff ff 48 89 c2 8b 45 ?? 48 63 d8 48 8b 45 e8 4c 8d 05 [2] 20 00 4c 89 e1 48 89 de 48 89 c7 b8 00 00 00 00 e8 [2] ff ff c7 45 ?? 78 [3] c7 45 ?? ba [3] c7 45 }
    condition: 
        uint32(0) == 0x464C457F and filesize > 15KB and all of them  
}
