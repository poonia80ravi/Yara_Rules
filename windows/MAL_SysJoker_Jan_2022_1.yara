rule MAL_SysJoker_Jan_2022_1
{
    meta:
        description = "Detect dropper of SysJoker backdoor"
        author = "Arkbird_SOLG"
        date = "2022-01-11"
        reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
        hash1 = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
        hash2 = "-"
        tlp = "Clear"
        adversary = "-"
        level = "Experimental"
    strings:
        $s1 = { 6a 00 ff 75 ec ff 15 00 f0 01 10 68 a8 a9 02 10 8d 8d ac fe ff ff c7 45 e8 00 00 00 00 e8 4c 1a 00 00 68 00 aa 02 10 8d 8d b0 fe ff ff c6 45 fc 0d e8 38 1a 00 00 68 10 aa 02 10 8d 8d b4 fe ff ff c6 45 fc 0e e8 24 1a 00 00 8d 45 cc c6 45 fc 0f 50 8d 95 b4 fe ff ff 8d 8d 84 fe ff ff e8 cb 18 00 00 8d 8d b0 fe ff ff c6 45 fc 10 51 8b d0 8d 8d }
        $s2 = { 68 40 a9 02 10 8d 4d cc c7 45 cc 00 00 00 00 e8 54 1c 00 00 c7 45 fc 00 00 00 00 8d 4d ec 68 64 a9 02 10 c7 45 ec 00 00 00 00 e8 39 1c 00 00 c6 45 fc 01 8d 8d bc fe ff ff 68 84 a9 02 10 c7 45 e4 00 00 00 00 e8 1e 1c 00 00 8d 85 bc fe ff ff c6 45 fc 02 50 8d 55 ec 8d 4d e4 e8 c8 1a 00 00 83 c4 04 c6 45 fc 04 83 ce ff 8b 95 bc fe ff ff 8b c6 83 c2 f0 f0 0f c1 42 0c 48 85 c0 7f 08 8b 0a 52 8b 01 ff 50 04 68 9c a9 02 10 8d 4d d0 c7 45 d0 00 00 00 00 e8 cd 1b 00 00 c6 45 fc 05 8d 8d b8 fe ff ff }
        $s3 = { 50 6a 00 6a 00 68 00 00 00 08 6a 00 6a 00 6a 00 ff 75 d4 6a 00 ff 15 54 f0 01 10 85 c0 74 1a 6a ff ff b5 78 ff ff ff ff d3 ff b5 78 ff ff ff ff d7 ff b5 7c ff ff ff ff d7 68 84 aa 02 10 8d 8d 98 fe ff ff c7 45 d8 00 00 00 00 e8 bb 16 00 00 68 90 aa 02 10 8d 8d 9c fe ff ff c6 45 fc 27 e8 a7 16 00 00 8d 45 e4 c6 45 fc 28 50 8d 95 9c fe ff ff 8d 8d 74 fe ff ff e8 4e 15 00 00 8d 8d 98 fe ff ff c6 45 fc 29 51 8b d0 8d 4d d8 e8 39 15 00 00 83 c4 08 c6 45 fc }
        $s4 = { 6a 00 6a 00 68 00 00 00 08 6a 00 6a 00 6a 00 ff 75 e8 6a 00 ff 15 54 f0 01 10 8b 1d 10 f0 01 10 8b 3d 2c f0 01 10 85 c0 74 1a 6a ff ff b5 78 ff ff ff ff d3 ff b5 78 ff ff ff ff d7 ff b5 7c ff ff ff ff d7 68 94 11 00 00 ff 15 1c f0 01 10 68 38 aa 02 10 8d 8d a0 fe ff ff c7 45 d4 00 00 00 00 e8 78 18 00 00 68 3c aa 02 10 8d 8d a4 fe ff ff c6 45 fc 1a e8 64 18 00 00 68 54 aa 02 10 8d 8d a8 fe ff ff c6 45 fc 1b e8 50 18 00 00 8d 45 e4 c6 45 fc 1c 50 8d 95 a8 fe ff }
	condition:
       uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
} 
