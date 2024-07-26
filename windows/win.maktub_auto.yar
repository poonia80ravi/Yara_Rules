rule win_maktub_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.maktub."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maktub"
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
        $sequence_0 = { ffd0 f7d8 1bc0 f7d8 8be5 }
            // n = 5, score = 400
            //   ffd0                 | call                eax
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax
            //   8be5                 | mov                 esp, ebp

        $sequence_1 = { c743f401000000 895de4 c6430100 0345d8 7413 6a01 }
            // n = 6, score = 300
            //   c743f401000000       | mov                 dword ptr [ebx - 0xc], 1
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   c6430100             | mov                 byte ptr [ebx + 1], 0
            //   0345d8               | add                 eax, dword ptr [ebp - 0x28]
            //   7413                 | je                  0x15
            //   6a01                 | push                1

        $sequence_2 = { ff15???????? eb0a 57 6a08 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   eb0a                 | jmp                 0xc
            //   57                   | push                edi
            //   6a08                 | push                8

        $sequence_3 = { ff15???????? eb02 33db 8b4df4 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   eb02                 | jmp                 4
            //   33db                 | xor                 ebx, ebx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_4 = { ff15???????? f6c301 7432 8b75b8 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   f6c301               | test                bl, 1
            //   7432                 | je                  0x34
            //   8b75b8               | mov                 esi, dword ptr [ebp - 0x48]

        $sequence_5 = { ff15???????? eb02 33c0 46 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   46                   | inc                 esi

        $sequence_6 = { ff7508 ffd0 89450c 83f8ff 754f 8b8384000000 6800800000 }
            // n = 7, score = 300
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd0                 | call                eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   83f8ff               | cmp                 eax, -1
            //   754f                 | jne                 0x51
            //   8b8384000000         | mov                 eax, dword ptr [ebx + 0x84]
            //   6800800000           | push                0x8000

        $sequence_7 = { ff15???????? f6c301 0f8414010000 8d46fc }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   f6c301               | test                bl, 1
            //   0f8414010000         | je                  0x11a
            //   8d46fc               | lea                 eax, [esi - 4]

        $sequence_8 = { ff7004 ff30 e8???????? 8bc7 5f 5e 5b }
            // n = 7, score = 200
            //   ff7004               | push                dword ptr [eax + 4]
            //   ff30                 | push                dword ptr [eax]
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_9 = { d2c5 660fbae905 f9 f6d8 }
            // n = 4, score = 100
            //   d2c5                 | rol                 ch, cl
            //   660fbae905           | bts                 cx, 5
            //   f9                   | stc                 
            //   f6d8                 | neg                 al

        $sequence_10 = { 8d4e34 e8???????? 5f 8bc6 5e c20400 }
            // n = 6, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20400               | ret                 4

        $sequence_11 = { d2c6 c6c614 f7d2 2c1c }
            // n = 4, score = 100
            //   d2c6                 | rol                 dh, cl
            //   c6c614               | mov                 dh, 0x14
            //   f7d2                 | not                 edx
            //   2c1c                 | sub                 al, 0x1c

        $sequence_12 = { 8d4e34 e8???????? 8d4e08 5e }
            // n = 4, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   e8????????           |                     
            //   8d4e08               | lea                 ecx, [esi + 8]
            //   5e                   | pop                 esi

        $sequence_13 = { d2c8 08c0 04f9 29fb }
            // n = 4, score = 100
            //   d2c8                 | ror                 al, cl
            //   08c0                 | or                  al, al
            //   04f9                 | add                 al, 0xf9
            //   29fb                 | sub                 ebx, edi

        $sequence_14 = { 8d4e34 e8???????? 6a03 8bce }
            // n = 4, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   e8????????           |                     
            //   6a03                 | push                3
            //   8bce                 | mov                 ecx, esi

        $sequence_15 = { 8d4e34 e8???????? 8d4e14 e8???????? }
            // n = 4, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   e8????????           |                     
            //   8d4e14               | lea                 ecx, [esi + 0x14]
            //   e8????????           |                     

        $sequence_16 = { 8d4e34 e8???????? 83664400 8d4e48 }
            // n = 4, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   e8????????           |                     
            //   83664400             | and                 dword ptr [esi + 0x44], 0
            //   8d4e48               | lea                 ecx, [esi + 0x48]

        $sequence_17 = { d2c4 66ffc0 8d4750 60 }
            // n = 4, score = 100
            //   d2c4                 | rol                 ah, cl
            //   66ffc0               | inc                 ax
            //   8d4750               | lea                 eax, [edi + 0x50]
            //   60                   | pushal              

        $sequence_18 = { 8d4e34 894508 8d4508 50 }
            // n = 4, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax

        $sequence_19 = { d2c8 660fbae406 0f91c0 83c701 }
            // n = 4, score = 100
            //   d2c8                 | ror                 al, cl
            //   660fbae406           | bt                  sp, 6
            //   0f91c0               | setno               al
            //   83c701               | add                 edi, 1

        $sequence_20 = { 8d4e34 e8???????? 8d4e44 e8???????? }
            // n = 4, score = 100
            //   8d4e34               | lea                 ecx, [esi + 0x34]
            //   e8????????           |                     
            //   8d4e44               | lea                 ecx, [esi + 0x44]
            //   e8????????           |                     

        $sequence_21 = { d2c4 660fc8 b806000000 f8 }
            // n = 4, score = 100
            //   d2c4                 | rol                 ah, cl
            //   660fc8               | bswap               ax
            //   b806000000           | mov                 eax, 6
            //   f8                   | clc                 

    condition:
        7 of them and filesize < 3063808
}