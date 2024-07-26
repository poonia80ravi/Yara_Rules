rule win_duuzer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.duuzer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.duuzer"
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
        $sequence_0 = { 83f804 7408 83c8ff e9???????? }
            // n = 4, score = 200
            //   83f804               | cmp                 eax, 4
            //   7408                 | je                  0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     

        $sequence_1 = { 4c89ac2470040000 ff15???????? 2521150000 8bc8 }
            // n = 4, score = 100
            //   4c89ac2470040000     | mov                 edi, 0xffffffff
            //   ff15????????         |                     
            //   2521150000           | dec                 esp
            //   8bc8                 | cmp                 dword ptr [ebx + 0x20], ebp

        $sequence_2 = { 014dec 66837dec00 0f8efc010000 0fbf45ec }
            // n = 4, score = 100
            //   014dec               | add                 dword ptr [esi + 0x48], ecx
            //   66837dec00           | add                 dword ptr [esi + 0x54], ecx
            //   0f8efc010000         | add                 dword ptr [esp + 0x10], eax
            //   0fbf45ec             | cmp                 edi, ebx

        $sequence_3 = { 00f4 c640001c c740008a460323 d188470383ee }
            // n = 4, score = 100
            //   00f4                 | mov                 eax, 0x9000
            //   c640001c             | mov                 ecx, 0x76b2
            //   c740008a460323       | nop                 
            //   d188470383ee         | cmp                 edi, eax

        $sequence_4 = { 4c89b350010100 e8???????? 488b5358 4903f6 }
            // n = 4, score = 100
            //   4c89b350010100       | xor                 edi, edi
            //   e8????????           |                     
            //   488b5358             | dec                 esp
            //   4903f6               | mov                 dword ptr [esp + 0x470], ebp

        $sequence_5 = { 014dec 83bf8400000000 7708 398780000000 }
            // n = 4, score = 100
            //   014dec               | je                  0x1c
            //   83bf8400000000       | mov                 edi, dword ptr [eax]
            //   7708                 | add                 dword ptr [ebp - 0x10], eax
            //   398780000000         | adc                 dword ptr [ebp - 0xc], edx

        $sequence_6 = { 0145f0 1155f4 85c9 7533 }
            // n = 4, score = 100
            //   0145f0               | cmp                 dword ptr [ebx + 0x18], 0
            //   1155f4               | je                  0xc
            //   85c9                 | inc                 ecx
            //   7533                 | mov                 eax, edi

        $sequence_7 = { 00e0 3541000436 41 0023 }
            // n = 4, score = 100
            //   00e0                 | mov                 edi, eax
            //   3541000436           | dec                 eax
            //   41                   | mov                 eax, dword ptr [ebx + 0x20]
            //   0023                 | dec                 esp

        $sequence_8 = { 4c89b348010100 48898358010100 488b4320 4885c0 }
            // n = 4, score = 100
            //   4c89b348010100       | mov                 dword ptr [ebx + 0xd0], ebp
            //   48898358010100       | dec                 eax
            //   488b4320             | mov                 dword ptr [ebx + 0xf8], 8
            //   4885c0               | inc                 ecx

        $sequence_9 = { 4c89b424e0050000 b800900000 b9b2760000 6690 }
            // n = 4, score = 100
            //   4c89b424e0050000     | mov                 dword ptr [ebx + 0x10158], eax
            //   b800900000           | dec                 eax
            //   b9b2760000           | mov                 eax, dword ptr [ebx + 0x20]
            //   6690                 | dec                 eax

        $sequence_10 = { 4c89abd0000000 48c783f800000008000000 41bfffffffff 4c396b20 }
            // n = 4, score = 100
            //   4c89abd0000000       | mov                 dword ptr [ebx + 0xd0], 8
            //   48c783f800000008000000     | dec    esp
            //   41bfffffffff         | mov                 dword ptr [ebx + 0xb8], ebp
            //   4c396b20             | mov                 dword ptr [esp + 0x20], 8

        $sequence_11 = { 4c8b1f 41837b1800 7405 418bc7 }
            // n = 4, score = 100
            //   4c8b1f               | mov                 eax, dword ptr [ebx + 0x20]
            //   41837b1800           | dec                 eax
            //   7405                 | test                eax, eax
            //   418bc7               | je                  0x1e

        $sequence_12 = { 010b 014e4c 014e48 014e54 }
            // n = 4, score = 100
            //   010b                 | dec                 esp
            //   014e4c               | mov                 dword ptr [esp + 0x5e0], esi
            //   014e48               | mov                 eax, 0x9000
            //   014e54               | mov                 ecx, 0x76b2

        $sequence_13 = { 01442410 3bfb 75c4 8b4630 }
            // n = 4, score = 100
            //   01442410             | nop                 
            //   3bfb                 | cmp                 edi, eax
            //   75c4                 | mov                 ebx, edi
            //   8b4630               | dec                 esp

        $sequence_14 = { 4c89abb0000000 4c89abb8000000 c744242008000000 e8???????? 85c0 750a }
            // n = 6, score = 100
            //   4c89abb0000000       | dec                 esp
            //   4c89abb8000000       | mov                 dword ptr [ebx + 0xb0], ebp
            //   c744242008000000     | dec                 esp
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [ebx + 0xb8], ebp
            //   750a                 | mov                 dword ptr [esp + 0x20], 8

    condition:
        7 of them and filesize < 491520
}