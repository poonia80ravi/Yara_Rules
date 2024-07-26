rule win_blindingcan_w0 {
   meta:
       author = "CISA Code & Media Analysis"
       incident = "10135536"
       date = "2018-05-04"
       actor = "Lazarus Group"
       actor_type = "APT"
       category = "malware"
       family = "BLINDINGCAN"
       description = "Detects 32bit HiddenCobra BLINDINGCAN Trojan RAT"
       hash = "1ee75106a9113b116c54e7a5954950065b809e0bb4dd0a91dc76f778508c7954"
       hash = "7dce6f30e974ed97a3ed024d4c62350f9396310603e185a753b63a1f9a2d5799"
       hash = "96721e13bae587c75618566111675dec2d61f9f5d16e173e69bb42ad7cb2dd8a"
       hash = "f71d67659baf0569143874d5d1c5a4d655c7d296b2e86be1b8f931c2335c0cd3"
       source = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
       malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blindingcan"
       malpedia_version = "20200901"
       malpedia_sharing = "TLP:WHITE"
       malpedia_license = ""
   strings:
       $s0 = { C7 45 EC 0D 06 09 2A C7 45 F0 86 48 86 F7 C7 45 F4 0D 01 01 01 C7 45 F8 05 00 03 82 }
       $s1 = { 50 4D 53 2A 2E 74 6D 70 }
       $s2 = { 79 67 60 3C 77 F9 BA 77 7A 56 1B 68 51 26 11 96 B7 98 71 39 82 B0 81 78 }
   condition:
       any of them
}
