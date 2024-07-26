rule MAL_ELF_DeimosC2_Beacon_Nov_2022_1 : deimosc2 beacon x64
{
   meta:
        description = "Detect the linux beacon used in the DeimosC2 framework (x64 version)"
        author = "Arkbird_SOLG"
        reference = "https://www.trendmicro.com/en_us/research/22/k/deimosc2-what-soc-analysts-and-incident-responders-need-to-know.html"
        date = "2022-11-08"
        hash1 = "05e9fe8e9e693cb073ba82096c291145c953ca3a3f8b3974f9c66d15c1a3a11d"
        hash2 = "23ec389d12c912ee895ec039891769d4be39a575caeca90615be7d4143b653c4"
        hash3 = "036947a130d99d024912ad8d6632ba6a32d5eb3649e2d605a0a6de5c6f35a63a"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 48 8d 84 24 ?? 00 00 00 48 89 44 24 18 48 c7 44 24 20 10 00 00 00 48 c7 44 24 28 10 00 00 00 [1-9] 89 44 24 30 48 89 ?? 24 38 48 8b 84 24 [2] 00 00 48 89 44 24 40 48 8b 84 24 [2] 00 00 48 89 44 24 48 48 8b 84 24 ?? 01 00 00 48 89 44 24 50 48 8b 84 24 ?? 01 00 00 48 89 44 24 58 e8 }
        $s2 = { 48 81 ec 20 02 00 00 48 89 ac 24 18 02 00 00 48 8d ac 24 18 02 00 00 80 3d [3] 00 01 0f 84 79 27 00 00 48 8b b4 24 30 02 00 00 48 8b 94 24 38 02 00 00 48 c1 ea 06 48 c1 e2 06 48 8d 3c 16 48 89 bc 24 00 01 00 00 48 39 fe 0f 84 3c 27 00 00 48 8b ac 24 28 02 00 00 44 8b 45 00 44 8b 4d 04 44 8b 55 08 44 8b 5d 0c 44 8b 65 10 44 8b 6d 14 44 8b 75 18 44 8b 7d 1c 48 89 e5 8b 06 0f c8 89 45 00 41 01 c7 44 89 e0 41 81 c7 98 2f 8a 42 44 89 e1 c1 c8 06 44 89 e2 c1 }
        $s3 = { 48 81 ec [2] 00 00 48 89 ac 24 [2] 00 00 48 8d ac 24 [2] 00 00 ?? c7 ?? 00 00 00 00 ?? 89 ?? 24 [2] 00 00 [6] 00 00 48 }
        $s4 = { 48 89 ac 24 00 01 00 00 48 8d ac 24 00 01 00 00 48 8b bc 24 10 01 00 00 48 8b 94 24 18 01 00 00 48 8b b4 24 30 01 00 00 4c 8b 8c 24 38 01 00 00 48 8b 8c 24 48 01 00 00 4c 8b 84 24 50 01 00 00 48 8b 84 24 58 01 00 00 4c 8b ac 24 60 01 00 00 49 c1 ed 02 49 ff cd f3 44 0f 6f 3d [3] 00 f3 44 0f 6f 35 [3] 00 f3 45 0f 6f 00 66 45 0f ef c9 66 45 0f ef d2 f3 0f 6f 01 44 8b 51 0c f3 44 0f 6f 18 44 8b 60 0c 41 0f ca 41 0f cc 66 44 0f ef d8 f3 44 0f 7f 9c 24 80 00 00 00 41 83 c2 01 45 89 d3 45 31 e3 41 0f cb 44 89 9c 24 8c 00 00 00 49 81 f9 80 00 00 00 0f 82 1e 10 00 00 49 81 }
   condition:
       uint32(0) == 0x464C457F and filesize > 300KB and all of ($s*)
}
