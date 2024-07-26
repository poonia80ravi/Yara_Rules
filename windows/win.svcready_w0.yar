rule win_svcready_w0 { 
   meta: 
        author = "@AndreGironda"
        description = "packed SVCReady / win.svcready"
        hash = "76d69ec491c0711f6cc60fbafcabf095"
        date = "June 8, 2022"
        tlp = "White"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.svcready"
        malpedia_rule_date = "20220608"
        malpedia_hash = ""
        malpedia_version = "20220609"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

   strings:
        $hex_1003b3e0 = { 52 75 6e 50 45 44 6c 6c 4e 61 74 69 76 65 3a 3a 46 69 6c 65 20 68 61 73 20 6e 6f 20 72 65 6c 6f 63 61 74 69 6f 6e }
        $hex_1003b424 = { 50 61 79 6c 6f 61 64 20 64 65 70 6c 6f 79 6d 65 6e 74 20 66 61 69 6c 65 64 2c 20 73 74 6f 70 70 69 6e 67 }
        $hex_1003c234 = { 4e 6f 74 20 73 75 70 70 6f 72 74 65 64 20 72 65 6c 6f 63 61 74 69 6f 6e 73 20 66 6f 72 6d 61 74 20 61 74 20 25 64 3a 20 25 64 0a 00 5b 2d 5d 20 }
        $hex_1003c2cc = { 49 6e 76 61 6c 69 64 20 61 64 64 72 65 73 73 20 6f 66 20 72 65 6c 6f 63 61 74 69 6f 6e 73 20 62 6c 6f 63 6b }

   condition:
        all of them
}
