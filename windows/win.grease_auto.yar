rule win_grease_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.grease."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grease"
        malpedia_rule_date = "20221007"
        malpedia_hash = "597f9539014e3d0f350c069cd804aa71679486ae"
        malpedia_version = "20221010"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 52 50 683f000f00 50 50 }
            // n = 5, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   683f000f00           | push                0xf003f
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_1 = { 48897c2430 4533c0 c74424283f000f00 897c2420 ff15???????? 85c0 }
            // n = 6, score = 300
            //   48897c2430           | dec                 eax
            //   4533c0               | mov                 dword ptr [esp + 0x280], eax
            //   c74424283f000f00     | dec                 eax
            //   897c2420             | lea                 ecx, [esp + 0x72]
            //   ff15????????         |                     
            //   85c0                 | dec                 eax

        $sequence_2 = { 488b4c2460 48897c2440 488d442450 4889442438 48897c2430 }
            // n = 5, score = 300
            //   488b4c2460           | mov                 ecx, dword ptr [esp + 0x60]
            //   48897c2440           | mov                 eax, 1
            //   488d442450           | dec                 eax
            //   4889442438           | mov                 ecx, dword ptr [esp + 0x280]
            //   48897c2430           | dec                 eax

        $sequence_3 = { 488d442458 41b904000000 4533c0 488bd3 c744242804000000 4889442420 }
            // n = 6, score = 300
            //   488d442458           | dec                 eax
            //   41b904000000         | lea                 eax, [esp + 0x58]
            //   4533c0               | inc                 ecx
            //   488bd3               | mov                 ecx, 4
            //   c744242804000000     | inc                 ebp
            //   4889442420           | xor                 eax, eax

        $sequence_4 = { 488b4c2460 ff15???????? b801000000 488b8c2480020000 4833cc }
            // n = 5, score = 300
            //   488b4c2460           | mov                 ecx, 4
            //   ff15????????         |                     
            //   b801000000           | inc                 ebp
            //   488b8c2480020000     | xor                 eax, eax
            //   4833cc               | dec                 eax

        $sequence_5 = { 4533c0 48c7c102000080 c74424281f000200 895c2420 ff15???????? 85c0 0f85e7000000 }
            // n = 7, score = 300
            //   4533c0               | dec                 eax
            //   48c7c102000080       | mov                 edx, ebx
            //   c74424281f000200     | mov                 dword ptr [esp + 0x28], 4
            //   895c2420             | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | mov                 dword ptr [esp + 0x20], eax
            //   0f85e7000000         | inc                 ebp

        $sequence_6 = { 488bd3 c744242804000000 4889442420 ff15???????? 488b4c2450 ff15???????? }
            // n = 6, score = 300
            //   488bd3               | dec                 eax
            //   c744242804000000     | mov                 ecx, dword ptr [esp + 0x280]
            //   4889442420           | dec                 eax
            //   ff15????????         |                     
            //   488b4c2450           | xor                 ecx, esp
            //   ff15????????         |                     

        $sequence_7 = { 85c0 7534 488b4c2450 488d442458 }
            // n = 4, score = 300
            //   85c0                 | dec                 eax
            //   7534                 | mov                 ecx, dword ptr [esp + 0x60]
            //   488b4c2450           | dec                 eax
            //   488d442458           | mov                 dword ptr [esp + 0x30], edi

        $sequence_8 = { 4053 4881ec90020000 488b05???????? 4833c4 4889842480020000 488d4c2472 }
            // n = 6, score = 300
            //   4053                 | mov                 edx, ebx
            //   4881ec90020000       | mov                 dword ptr [esp + 0x28], 4
            //   488b05????????       |                     
            //   4833c4               | jne                 0x36
            //   4889842480020000     | dec                 eax
            //   488d4c2472           | mov                 ecx, dword ptr [esp + 0x50]

        $sequence_9 = { e9???????? c68434340a000077 e9???????? c68434340a000076 e9???????? c68434340a000065 e9???????? }
            // n = 7, score = 200
            //   e9????????           |                     
            //   c68434340a000077     | mov                 byte ptr [esp + esi + 0xa34], 0x77
            //   e9????????           |                     
            //   c68434340a000076     | mov                 byte ptr [esp + esi + 0xa34], 0x76
            //   e9????????           |                     
            //   c68434340a000065     | mov                 byte ptr [esp + esi + 0xa34], 0x65
            //   e9????????           |                     

        $sequence_10 = { e9???????? c68434100100005f e9???????? c68434100100003a }
            // n = 4, score = 200
            //   e9????????           |                     
            //   c68434100100005f     | mov                 byte ptr [esp + esi + 0x110], 0x5f
            //   e9????????           |                     
            //   c68434100100003a     | mov                 byte ptr [esp + esi + 0x110], 0x3a

        $sequence_11 = { 8d442420 50 8d4c1202 51 8d942434010000 }
            // n = 5, score = 200
            //   8d442420             | jne                 0x36
            //   50                   | dec                 eax
            //   8d4c1202             | mov                 ecx, dword ptr [esp + 0x50]
            //   51                   | dec                 eax
            //   8d942434010000       | lea                 eax, [esp + 0x58]

        $sequence_12 = { c6440c0c74 e9???????? c6440c0c67 e9???????? c6440c0c61 }
            // n = 5, score = 200
            //   c6440c0c74           | mov                 byte ptr [esp + ecx + 0xc], 0x74
            //   e9????????           |                     
            //   c6440c0c67           | mov                 byte ptr [esp + ecx + 0xc], 0x67
            //   e9????????           |                     
            //   c6440c0c61           | mov                 byte ptr [esp + ecx + 0xc], 0x61

        $sequence_13 = { 68???????? bf01000000 50 897c2430 ffd5 8b542410 }
            // n = 6, score = 200
            //   68????????           |                     
            //   bf01000000           | dec                 eax
            //   50                   | mov                 dword ptr [esp + 0x30], edi
            //   897c2430             | inc                 ebp
            //   ffd5                 | xor                 eax, eax
            //   8b542410             | mov                 dword ptr [esp + 0x28], 0xf003f

        $sequence_14 = { c68434340a00007d e9???????? c68434340a000029 e9???????? c68434340a00003b }
            // n = 5, score = 200
            //   c68434340a00007d     | mov                 byte ptr [esp + esi + 0xa34], 0x7d
            //   e9????????           |                     
            //   c68434340a000029     | mov                 byte ptr [esp + esi + 0xa34], 0x29
            //   e9????????           |                     
            //   c68434340a00003b     | mov                 byte ptr [esp + esi + 0xa34], 0x3b

        $sequence_15 = { c68434280700003b e9???????? c68434280700002b e9???????? }
            // n = 4, score = 200
            //   c68434280700003b     | mov                 byte ptr [esp + esi + 0x728], 0x3b
            //   e9????????           |                     
            //   c68434280700002b     | mov                 byte ptr [esp + esi + 0x728], 0x2b
            //   e9????????           |                     

        $sequence_16 = { 53 68???????? 52 895c2430 ffd5 8b442410 50 }
            // n = 7, score = 200
            //   53                   | test                eax, eax
            //   68????????           |                     
            //   52                   | jne                 0xef
            //   895c2430             | dec                 eax
            //   ffd5                 | mov                 ecx, dword ptr [esp + 0x60]
            //   8b442410             | dec                 eax
            //   50                   | xor                 eax, esp

        $sequence_17 = { c6440c086c e9???????? c6440c0864 e9???????? c6440c0870 e9???????? c6440c0873 }
            // n = 7, score = 200
            //   c6440c086c           | mov                 byte ptr [esp + ecx + 8], 0x6c
            //   e9????????           |                     
            //   c6440c0864           | mov                 byte ptr [esp + ecx + 8], 0x64
            //   e9????????           |                     
            //   c6440c0870           | mov                 byte ptr [esp + ecx + 8], 0x70
            //   e9????????           |                     
            //   c6440c0873           | mov                 byte ptr [esp + ecx + 8], 0x73

        $sequence_18 = { c68434100100002a e9???????? c684341001000026 eb76 c68434100100005b eb6c c684341001000040 }
            // n = 7, score = 200
            //   c68434100100002a     | mov                 byte ptr [esp + esi + 0x110], 0x2a
            //   e9????????           |                     
            //   c684341001000026     | mov                 byte ptr [esp + esi + 0x110], 0x26
            //   eb76                 | jmp                 0x78
            //   c68434100100005b     | mov                 byte ptr [esp + esi + 0x110], 0x5b
            //   eb6c                 | jmp                 0x6e
            //   c684341001000040     | mov                 byte ptr [esp + esi + 0x110], 0x40

        $sequence_19 = { 51 ff15???????? 8d442404 83c0ff }
            // n = 4, score = 200
            //   51                   | lea                 eax, [esp + 0x58]
            //   ff15????????         |                     
            //   8d442404             | dec                 eax
            //   83c0ff               | mov                 dword ptr [esp + 0x38], eax

        $sequence_20 = { 6689842432010000 6689842438010000 b904000000 8d442420 50 66898c2432010000 }
            // n = 6, score = 200
            //   6689842432010000     | inc                 ecx
            //   6689842438010000     | mov                 ecx, 4
            //   b904000000           | inc                 ebp
            //   8d442420             | xor                 eax, eax
            //   50                   | dec                 eax
            //   66898c2432010000     | mov                 edx, ebx

        $sequence_21 = { 6a04 8d4c241c 51 6a04 53 68???????? 52 }
            // n = 7, score = 200
            //   6a04                 | mov                 dword ptr [esp + 0x20], ebx
            //   8d4c241c             | test                eax, eax
            //   51                   | jne                 0xf3
            //   6a04                 | dec                 eax
            //   53                   | mov                 ecx, dword ptr [esp + 0x60]
            //   68????????           |                     
            //   52                   | dec                 eax

        $sequence_22 = { 8d442420 68???????? 50 e8???????? 83c428 85c0 7409 }
            // n = 7, score = 200
            //   8d442420             | dec                 eax
            //   68????????           |                     
            //   50                   | mov                 dword ptr [esp + 0x280], eax
            //   e8????????           |                     
            //   83c428               | dec                 eax
            //   85c0                 | lea                 ecx, [esp + 0x72]
            //   7409                 | mov                 dword ptr [esp + 0x28], 0x2001f

    condition:
        7 of them and filesize < 278528
}