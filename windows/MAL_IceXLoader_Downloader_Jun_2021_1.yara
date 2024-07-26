rule MAL_IceXLoader_Downloader_Jun_2021_1 : icexloader downloader nim v3
{
    meta:
        description = "Detect the downloader that drops IceXLoader loader (nim version)"
        author = "Arkbird_SOLG"
        date = "2022-06-19"
        reference = "https://www.fortinet.com/blog/threat-research/new-icexloader-3-0-developers-warm-up-to-nim"
        hash1 = "705e8d65983d6f6ecdce444dea17e33642b7bb3336f627698ac5d32637efcb18"
        hash2 = "ce830f802b7fdb4d42c18bd692690cfac0e2d03947c6b13f583af215a7039b54"
        hash3 = "11881702372ebdeb3b2386a3dd1a6e8f40374867317ffcd23b74c892502cc6af"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 00 20 00 0c 00 00 28 29 00 00 0a 00 00 de 05 26 00 00 de 00 03 28 2a 00 00 0a 74 17 00 00 01 0a 06 6f 2b 00 00 0a 74 18 00 00 01 0b 07 6f 2c 00 00 0a 0c 08 }
        $s2 = { 0a 73 1d 00 00 0a 0b 07 6f 1e 00 00 0a 72 0d 00 00 70 6f 1f 00 00 0a 00 07 6f 1e 00 00 0a 72 15 00 00 70 6f 20 00 00 0a 00 07 6f 1e 00 00 0a 17 6f 21 00 00 0a 00 07 6f 22 00 00 0a 26 2b 02 00 00 07 6f 23 00 00 0a 16 fe 01 0c 08 2d f1 06 16 06 8e 69 28 24 00 00 0a 00 06 }
        $s3 = { 00 73 25 00 00 0a 0a 02 03 28 08 00 00 06 06 6f 26 00 00 0a 00 06 6f 27 00 00 0a 0b 06 6f 28 00 00 0a 00 07 0c 2b 00 08 2a }
        $s4 = { 00 02 02 72 49 00 00 70 28 07 00 00 06 28 06 00 00 06 28 2d 00 00 0a 0a 2b 00 06 2a }
    condition:
        uint16(0) == 0x5A4D and filesize > 20KB and all of ($s*) 
}
