rule MAL_BPFDoor_May_2022_2 : apt bpfdoor controller redmenshen x64
{
   meta:
        description = "Detect BPFDoor used by Red Menshen"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-07"
        updated = "2022-05-17"
        hash1 = "dfdabe9013e783535a76407b61b63e97db283daab202218077cc0b846b3caa42"
        hash2 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
        hash3 = "bd353a28886815f43fe71c561a027fdeff5cd83e17e2055c0e52bea344ae51d3"
        hash4 = "fe9f3b7451913f184e1f53b52a03a981dcea5564633cfcb70d01bd0aec8f30a7"
        tlp = "Clear"
        adversary = "Red Menshen"
   strings:
        $s1 = { f3 48 ab c6 85 ?? f9 ff ff 2f c6 85 ?? f9 ff ff 73 c6 85 ?? f9 ff ff 62 c6 85 ?? f9 ff ff 69 c6 85 ?? f9 ff ff 6e c6 85 ?? f9 ff ff 2f c6 85 ?? f9 ff ff 69 c6 85 ?? f9 ff ff 70 c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 61 c6 85 ?? f9 ff ff 62 c6 85 ?? f9 ff ff 6c c6 85 ?? f9 ff ff 65 c6 85 ?? f9 ff ff 73 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 6e c6 85 ?? f9 ff ff 61 c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 41 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 50 c6 85 ?? f9 ff ff 52 c6 85 ?? f9 ff ff 45 c6 85 ?? f9 ff ff 52 c6 85 ?? f9 ff ff 4f c6 85 ?? f9 ff ff 55 c6 85 ?? f9 ff ff 54 c6 85 ?? f9 ff ff 49 c6 85 ?? f9 ff ff 4e c6 85 ?? f9 ff ff 47 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 70 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 63 c6 85 ?? f9 ff ff 70 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 73 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 25 c6 85 ?? f9 ff ff 73 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 64 c6 85 ?? f9 ff ff 70 c6 85 ?? f9 ff ff 6f c6 85 ?? f9 ff ff 72 c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 25 c6 85 ?? f9 ff ff 64 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 6a c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 52 c6 85 ?? f9 ff ff 45 c6 85 ?? f9 ff ff 44 c6 85 ?? f9 ff ff 49 c6 85 ?? f9 ff ff 52 c6 85 ?? f9 ff ff 45 c6 85 ?? f9 ff ff 43 c6 85 ?? f9 ff ff 54 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 6f c6 85 ?? f9 ff ff 2d c6 85 ?? f9 ff ff 70 c6 85 ?? f9 ff ff 6f c6 85 ?? f9 ff ff 72 c6 85 ?? f9 ff ff 74 c6 85 ?? f9 ff ff 73 c6 85 ?? f9 ff ff 20 c6 85 ?? f9 ff ff 25 c6 85 ?? f9 ff ff 64 c6 85 ?? f9 ff ff 00 c6 85 ?? f9 ff ff 2f c6 85 ?? f9 ff }
        $s2 = { c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 [2] c6 45 }
        $s3 = { be 10 00 00 00 [2-6] ff ff 8b 45 ?? 89 45 e4 ba 00 00 00 00 be 01 00 00 00 bf 02 00 00 00 e8 [2] ff ff 89 45 ?? 83 7d ?? ff 75 [2-4] ff ff ff ff eb ?? 66 c7 45 e0 02 00 0f b7 45 ?? 66 89 45 e2 48 8d ?? e0 8b [2] ba 10 00 00 00 [3-8] ff ff 83 f8 ff 75 11 8b [2-4] e8 [2] ff ff [1-3] ff ff ff ff eb }
   condition:
        uint32(0) == 0x464C457F and filesize > 10KB and all of ($s*)
}
