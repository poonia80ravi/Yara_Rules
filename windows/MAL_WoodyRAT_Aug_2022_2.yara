rule MAL_WoodyRAT_Aug_2022_2 : woodyrat x86
{
    meta:
        description = "Detect WoodyRAT implant"
        author = "Arkbird_SOLG"
        date = "2022-08-04"
        reference = "https://blog.malwarebytes.com/threat-intelligence/2022/08/woody-rat-a-new-feature-rich-malware-spotted-in-the-wild/"
        hash1 = "3ba32825177d7c2aac957ff1fc5e78b64279aeb748790bc90634e792541de8d3"
        hash2 = "5c5020ee0f7a5b78a6da74a3f58710cba62f727959f8ece795b0f47828e33e80"
        hash3 = "9bc071fb6a1d9e72c50aec88b4317c3eb7c0f5ff5906b00aa00d9e720cbc828d"
        tlp = "Clear"
        adversary = "Woody" // internal name reference [WoodyRAT - WoodyPowerSession - WoodySharpExecutor]
    strings:
        $s1 = { 50 c7 85 ?? df ff ff 00 00 00 00 c7 85 ?? df ff ff 00 00 00 00 c7 85 ?? df ff ff 00 00 00 00 c7 85 ?? df ff ff 00 00 00 00 e8 [3] 00 8b 4f ?? 83 ec 0c 0f 57 c0 83 c1 0c 0f 11 85 ?? f3 ff ff 54 e8 [4] 8d 8d ?? f3 ff ff e8 [4] 83 c4 18 c7 45 fc 00 00 00 00 8d 8d ?? f3 ff ff 6a 1b 33 c0 c7 85 ?? f3 ff ff 00 00 00 00 68 [3] 00 c7 85 ?? f3 ff ff 07 00 00 00 66 89 85 ?? f3 ff ff e8 [3] ff 6a ?? 68 [3] 00 8d 8d ?? f3 ff ff c6 45 fc 01 e8 [4] 83 bd ?? f3 ff ff 08 8d 85 ?? f3 ff ff ff b5 ?? f3 ff ff 0f 43 85 ?? f3 ff ff 8d 8d ?? f3 ff ff 50 e8 [4] 83 bd ?? f3 ff ff 08 8d 85 ?? f3 ff ff 8d 95 f0 f3 ff ff 0f 43 85 ?? f3 ff ff 2b d0 0f 1f 40 00 0f b7 08 8d 40 02 66 89 4c 02 fe 66 85 c9 75 f0 8b 35 [2] 44 00 8d 85 ?? df ff ff 6a 00 50 8d 85 ?? df ff ff c7 85 ?? df ff ff 0c 00 00 00 50 8d 85 ?? df ff ff c7 85 ?? df ff ff 00 00 00 00 50 c7 85 ?? df ff ff 01 00 00 00 ff d6 85 c0 0f 84 ?? 03 00 00 6a 00 8d 85 ?? df ff ff }
        $s2 = { 0f 57 c0 c7 45 ?? 00 00 00 00 66 0f d6 ?? c7 ?? 08 00 00 00 00 c7 ?? 00 00 00 00 c7 ?? 04 00 00 00 00 c7 ?? 08 00 00 00 00 c7 45 fc 00 00 00 00 8d 8d [2] ff ff 6a 0e 33 c0 c7 45 ?? 01 00 00 00 68 [3] 00 66 0f d6 45 e4 c7 45 ec 00 00 00 00 c7 85 ?? ff ff ff 00 00 00 00 c7 85 ?? ff ff ff 07 00 00 00 66 89 85 [2] ff ff e8 [2] fe ff c7 45 fc 01 00 00 00 8d 8d ?? ff ff ff 6a 0a 33 c0 c7 85 ?? ff ff ff 00 00 00 00 68 [3] 00 c7 85 ?? ff ff ff 07 00 00 00 66 89 85 ?? ff ff ff e8 [2] fe ff c6 45 fc 02 8d 8d ?? ff ff ff 6a 0c 33 c0 c7 85 ?? ff ff ff 00 00 00 00 68 [3] 00 c7 85 ?? ff ff ff 07 00 00 00 66 89 85 ?? ff ff ff e8 [2] fe ff c6 45 fc 03 8d 8d ?? ff ff ff 6a 03 33 c0 c7 85 ?? ff ff ff 00 00 00 00 68 [3] 00 c7 85 ?? ff ff ff 07 00 00 00 66 89 85 ?? ff ff ff e8 [2] fe ff c6 45 fc 04 8d 8d ?? ff ff ff 6a 04 33 c0 c7 }
        $s3 = { 8d 44 24 18 50 ff 36 ff 15 [2] 44 00 8b 7c 24 18 b8 [3] 00 8b cf 0f 1f 80 00 00 00 00 66 8b 11 66 3b 10 75 1e 66 85 d2 74 15 66 8b 51 02 66 3b }
        $s4 = { 8b c1 89 85 ?? fe ff ff 89 85 ?? fe ff ff 89 85 ?? fe ff ff c7 85 ?? fe ff ff 00 00 00 00 c7 00 00 00 00 00 c7 40 04 00 00 00 00 c7 40 08 00 00 00 00 c7 40 0c 00 00 00 00 c7 40 10 00 00 00 00 c7 40 14 00 00 00 00 c7 40 18 00 00 00 00 c7 40 1c 00 00 00 00 c7 40 20 00 00 00 00 c7 45 fc 00 00 00 00 8d 8d }
        $s5 = "S-1-5-32-544" wide // intergated administrators group
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
} 
