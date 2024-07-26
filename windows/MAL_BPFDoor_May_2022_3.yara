rule MAL_BPFDoor_May_2022_3 : apt bpfdoor controller redmenshen x86
{
   meta:
        description = "Detect BPFDoor used by Red Menshen"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-07"
        hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        hash2 = "54a4b3c2ac34f1913634ab9be5f85cde19445d01260bb15bcd1d52ebcc85af2c"
        tlp = "Clear"
        adversary = "Red Menshen"
   strings:
        $s1 = { c6 85 ?? 7b ff ff 2f c6 85 ?? 7b ff ff 62 c6 85 ?? 7b ff ff 69 c6 85 ?? 7b ff ff 6e c6 85 ?? 7b ff ff 2f c6 85 ?? 7b ff ff 73 c6 85 ?? 7b ff ff 68 c6 85 ?? 7b ff ff 00 c6 85 ?? 7b ff ff 48 c6 85 ?? 7b ff ff 4f c6 85 ?? 7b ff ff 4d c6 85 ?? 7b ff ff 45 c6 85 ?? 7b ff ff 3d c6 85 ?? 7b ff ff 2f c6 85 ?? 7b ff ff 74 c6 85 ?? 7b ff ff 6d c6 85 ?? 7b ff ff 70 c6 85 ?? 7b ff ff 00 }
        $s2 = { ff ff [0-3] c7 45 ?? fe ff ff ff eb (6e 83 ec 0c ff 75 f8 | 63 8b 45 fc 89 04 24 ) e8 [2] ff ff }
        $s3 = { 02 53 00 00 [2] fc ( e8 b9 f2 | 89 04 24 e8 fd e8 ) ff ff [0-3] 85 c0 79 08 8b 45 fc 89 45 ?? eb ( 4e 83 ec 04 68 9d ae | 54 c7 44 24 08 aa c4 ) 04 08  }
        $s4 = { ff ff [0-3] 89 45 ?? 83 7d ?? ff 75 09 c7 45 ?? ff ff ff ff eb ?? 66 c7 45 ?? 02 00 [2] 45 ?? 66 89 45 [2-3] ec }
   condition:
        uint32(0) == 0x464C457F and filesize > 10KB and all of ($s*)
}
