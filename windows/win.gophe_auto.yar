rule win_gophe_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gophe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gophe"
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
        $sequence_0 = { 833902 0f94c0 84c0 7407 }
            // n = 4, score = 300
            //   833902               | cmp                 dword ptr [ecx], 2
            //   0f94c0               | sete                al
            //   84c0                 | test                al, al
            //   7407                 | je                  9

        $sequence_1 = { 2bf0 b8abaaaa2a f7ee c1fa03 }
            // n = 4, score = 200
            //   2bf0                 | sub                 esi, eax
            //   b8abaaaa2a           | mov                 eax, 0x2aaaaaab
            //   f7ee                 | imul                esi
            //   c1fa03               | sar                 edx, 3

        $sequence_2 = { 68???????? 8d85fcfdffff 68f4010000 50 }
            // n = 4, score = 200
            //   68????????           |                     
            //   8d85fcfdffff         | lea                 eax, [ebp - 0x204]
            //   68f4010000           | push                0x1f4
            //   50                   | push                eax

        $sequence_3 = { 894104 418b01 894108 418b4104 }
            // n = 4, score = 200
            //   894104               | mov                 ecx, ebx
            //   418b01               | test                eax, eax
            //   894108               | jne                 0xaf
            //   418b4104             | inc                 ebp

        $sequence_4 = { 51 6a00 6a00 6a00 50 68???????? }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_5 = { 0f94c0 84c0 745b e8???????? }
            // n = 4, score = 200
            //   0f94c0               | sete                al
            //   84c0                 | test                al, al
            //   745b                 | je                  0x5d
            //   e8????????           |                     

        $sequence_6 = { 83781408 7202 8b00 51 6a00 }
            // n = 5, score = 200
            //   83781408             | cmp                 dword ptr [eax + 0x14], 8
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_7 = { 55 8bec 837d0800 7507 b802000000 5d }
            // n = 6, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7507                 | jne                 9
            //   b802000000           | mov                 eax, 2
            //   5d                   | pop                 ebp

        $sequence_8 = { 7417 4c8bc8 ba11010000 41b808000000 }
            // n = 4, score = 200
            //   7417                 | je                  0x19
            //   4c8bc8               | dec                 esp
            //   ba11010000           | mov                 ecx, eax
            //   41b808000000         | mov                 edx, 0x111

        $sequence_9 = { 7407 e8???????? eb06 e8???????? 90 488d8c24b8000000 }
            // n = 6, score = 200
            //   7407                 | je                  0x37
            //   e8????????           |                     
            //   eb06                 | cmp                 byte ptr [ecx], 0x5c
            //   e8????????           |                     
            //   90                   | jne                 0x32
            //   488d8c24b8000000     | dec                 eax

        $sequence_10 = { 6a04 ff15???????? 50 8d442414 }
            // n = 4, score = 200
            //   6a04                 | push                4
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_11 = { 01771c 83c40c 8bc6 33d2 }
            // n = 4, score = 200
            //   01771c               | add                 dword ptr [edi + 0x1c], esi
            //   83c40c               | add                 esp, 0xc
            //   8bc6                 | mov                 eax, esi
            //   33d2                 | xor                 edx, edx

        $sequence_12 = { 7435 80395c 752d 48ffc1 483bc8 }
            // n = 5, score = 200
            //   7435                 | mov                 eax, dword ptr [edi]
            //   80395c               | mov                 dword ptr [edi + 8], 0xffffffff
            //   752d                 | mov                 edx, dword ptr [eax + 0x14]
            //   48ffc1               | dec                 eax
            //   483bc8               | test                esi, esi

        $sequence_13 = { 7408 488b0f e8???????? 488b07 c74708ffffffff 8b5014 4885f6 }
            // n = 7, score = 200
            //   7408                 | inc                 ecx
            //   488b0f               | mov                 eax, 8
            //   e8????????           |                     
            //   488b07               | je                  0xa
            //   c74708ffffffff       | dec                 eax
            //   8b5014               | mov                 ecx, dword ptr [edi]
            //   4885f6               | dec                 eax

        $sequence_14 = { 7406 c706ffffffff 4885db 7416 33d2 41b830020000 }
            // n = 6, score = 200
            //   7406                 | jmp                 0xa
            //   c706ffffffff         | nop                 
            //   4885db               | dec                 eax
            //   7416                 | lea                 ecx, [esp + 0xb8]
            //   33d2                 | je                  0x37
            //   41b830020000         | cmp                 byte ptr [ecx], 0x5c

        $sequence_15 = { 85c0 0f85a9000000 4533c9 4533c0 }
            // n = 4, score = 200
            //   85c0                 | dec                 eax
            //   0f85a9000000         | mov                 ecx, dword ptr [edi]
            //   4533c9               | dec                 eax
            //   4533c0               | mov                 eax, dword ptr [edi]

    condition:
        7 of them and filesize < 1582080
}