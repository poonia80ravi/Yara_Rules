rule MAL_HeaderTip_Mar_2022_1 : headerTip uac0026
{
   meta:
      description = "Detect HeaderTip used uac0026 group (detect also the installers)"
      author = "Arkbird_SOLG"
      reference = "https://cert.gov.ua/article/38097"
      date = "2022-03-22"
      hash1 = "b1ba84107958ac79181ad1089096bb134d069d9842440327d972797b959b9193"
      hash2 = "63a218d3fc7c2f7fcadc0f6f907f326cc86eb3f8cf122704597454c34c141cf1"
      hash3 = "0a146f2f566f6130dfed9ee842fce3229efff8a751062cb3ad5dac137807b712"
      adversary = "UAC-0026"
      tlp = "Clear"
   strings:
      $s1 = { 8a 4d f0 8b 45 08 88 08 8b 45 0c 8a 4d f1 88 08 8b 45 f4 8b 4d 14 56 8b 75 10 89 01 83 26 00 85 c0 74 2a 50 ff 15 20 30 00 10 59 89 06 85 c0 74 18 ff 75 f4 50 e8 [4] 59 59 85 c0 75 0d ff 36 ff 15 1c 30 00 10 59 33 c0 eb 03 33 c0 40 }
      $s2 = { 57 83 c0 08 68 14 31 00 10 50 ff 15 40 30 00 10 8b f8 59 59 3b fb 0f 84 a3 00 00 00 53 56 57 ff 15 3c 30 00 10 83 c4 0c 85 c0 0f 85 8f 00 00 00 8d 45 10 50 8d 45 fc 50 8d 45 08 50 8d 45 0f 50 e8 [4] 83 c4 10 85 c0 74 51 8b 35 1c 30 00 }
      $s3 = { 8b ec 81 ec 1c 01 00 00 56 68 24 31 00 10 8d 85 e4 fe ff ff 50 c6 45 ec 00 c6 45 e8 00 c7 05 a4 42 01 10 01 00 00 00 c7 05 8c 42 00 10 50 46 00 00 ff 15 10 30 00 10 ff 35 8c 42 00 10 ff 15 0c 30 00 10 68 17 ca 2b 6e e8 15 ff ff ff 8b f0 89 35 94 42 00 10 83 fe ff 75 1e 68 3f d6 ec 8f e8 fe fe ff ff 8b f0 89 35 94 42 00 10 83 fe }
      $s4 = { 8b ec 81 ec 8c 00 00 00 56 57 6a 23 59 be 88 30 00 10 8d bd 74 ff ff ff f3 a5 33 ff 57 68 38 02 00 00 68 38 40 00 10 e8 [2] 00 00 e8 [2] 00 00 8d 85 74 ff ff ff 50 68 80 30 00 10 be 4c 40 00 10 56 c7 05 38 40 00 10 [2] 00 10 c7 05 3c 40 00 10 [2] 00 10 ff 15 18 40 00 10 83 c4 18 e8 [4] a3 60 42 00 10 89 15 64 42 00 10 ff 15 00 30 00 10 a3 68 42 00 10 33 c0 83 7d 10 01 57 0f 95 c0 57 57 50 56 ff 15 1c 40 00 10 a3 40 40 00 10 3b c7 74 21 8b 45 08 a3 4c 42 00 10 8b 45 0c a3 }
      $s5 = { 56 57 6a 58 33 f6 8d 45 a8 56 50 e8 [2] 00 00 a1 5c 42 00 10 89 45 b0 a1 60 42 00 10 89 45 a8 a1 64 42 00 10 6a 58 89 45 ac 8d 45 a8 50 56 ff 75 08 c7 45 bc 00 00 02 00 56 c7 45 c0 [3] 00 89 75 b4 c6 45 e6 03 e8 [4] 8b f8 83 c4 20 3b fe }
   condition:
      uint16(0) == 0x5A4D and filesize > 5KB and all of ($s*)
}
