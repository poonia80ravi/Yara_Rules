rule MAL_HttpService_Feb_2022_1 : HttpService Backdoor
{
   meta:
        description = "Detect the HttpService backdoor used against Iranian infrastructures"
        // have some copy/paste functions with Winscreeny
        author = "Arkbird_SOLG"
        reference = "https://research.checkpoint.com/2022/evilplayout-attack-against-irans-state-broadcaster/"
        date = "2022-02-17"
        hash1 = "096bae94e09059e2e3106503353b1b4f7116fa667600ca2ab3fa7591708e645a"
        hash2 = "e3d61cbbfbe41295dd52acff388d1d8b1d414a143d77def4221fd885aae6cd83"
        hash3 = "13a016b8f502c81e172c09114f25e4d8a8632768aefd56c5f6d147e9b6466216"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 7e ?? 00 00 0a 02 28 14 00 00 06 73 ?? 00 00 0a 0a 06 6f ?? 00 00 0a 00 73 39 00 00 06 25 02 7d 12 00 00 04 25 06 6f ?? 00 00 0a 7d 11 00 00 04 fe 06 3a 00 00 06 73 ?? 00 00 0a 73 ?? 00 00 0a 28 ?? 00 00 0a de d0 0b 72 75 02 00 70 07 6f ?? 00 00 0a 28 ?? 00 00 0a de bd }
        $s2 = { 02 03 28 1b 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 25 0d 72 d4 04 00 70 09 6f 10 00 00 06 13 04 12 04 28 ?? 00 00 0a 72 1a 05 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 7a 00 02 05 28 1b 00 00 06 6f ?? 00 00 0a 0b de 18 26 72 30 05 00 70 0f 03 28 ?? 00 00 0a 28 ?? 00 00 0a 73 ?? 00 00 0a 7a 00 02 1f 14 28 1a 00 00 06 6f ?? 00 00 0a 0c de 27 13 05 72 90 05 00 70 11 05 6f 10 00 00 06 13 04 12 04 28 ?? 00 00 0a 72 1a 05 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 7a 02 04 28 24 00 00 06 25 72 d8 05 00 70 08 6f ?? 00 00 0a 25 72 87 02 00 70 06 6f ?? 00 00 0a 25 72 f0 05 00 70 07 6f ?? 00 00 0a }
        $s3 = { 85 02 00 70 0a 72 85 02 00 70 0b 72 b6 06 00 70 73 ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 28 ?? 00 00 0a 6f ?? 00 00 0a 25 28 ?? 00 00 0a 6f ?? 00 00 0a 25 72 c6 06 00 70 03 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 25 6f ?? 00 00 0a 0c 25 6f ?? 00 00 0a 25 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 08 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a de 29 0d 09 6f ?? 00 00 0a 0b 09 6f ?? 00 00 0a 2c 17 07 72 f2 06 00 70 09 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b de 00 18 8d ?? 00 00 01 25 16 06 a2 25 17 07 a2 }
        $x1 = { 02 73 [2] 00 0a 7d ?? 00 00 04 02 7b ?? 00 00 04 6f [2] 00 0a 72 ?? 1c 00 70 02 7c ?? 00 00 04 28 ?? 00 00 0a 72 ?? 19 00 70 28 ?? 00 00 0a 6f [2] 00 0a 02 7b ?? 00 00 04 6f [2] 00 0a }
        $x2 = { 11 ?? 72 ?? ?? 00 70 11 ?? 17 9a 6f ?? 00 00 0a 26 02 03 11 ?? 6f ?? 00 00 0a ?? ?? ?? 00 }
        $x3 = { 02 03 7d ?? 00 00 04 02 02 fe 06 ?? 00 00 06 73 ?? 01 00 0a 73 ?? 01 00 0a 7d ?? 00 00 04 02 7b ?? 00 00 04 17 6f ?? 01 00 0a 02 7b ?? 00 00 04 6f ?? 01 00 0a }
    condition:
        uint16(0) == 0x5A4D and filesize > 10KB and ( all of ($s*) or all of ($x*) ) 
}
