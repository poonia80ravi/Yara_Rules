rule win_nachocheese_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.nachocheese."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nachocheese"
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
        $sequence_0 = { 2bfa 8d47fd 3901 8901 }
            // n = 4, score = 300
            //   2bfa                 | sub                 edi, edx
            //   8d47fd               | lea                 eax, [edi - 3]
            //   3901                 | cmp                 dword ptr [ecx], eax
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_1 = { 397508 0f8ec9000000 b8???????? 48 }
            // n = 4, score = 300
            //   397508               | cmp                 dword ptr [ebp + 8], esi
            //   0f8ec9000000         | jle                 0xcf
            //   b8????????           |                     
            //   48                   | dec                 eax

        $sequence_2 = { 33c8 894710 8b4708 33c1 }
            // n = 4, score = 300
            //   33c8                 | xor                 ecx, eax
            //   894710               | mov                 dword ptr [edi + 0x10], eax
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   33c1                 | xor                 eax, ecx

        $sequence_3 = { 32d1 88143e 8a4805 02ca }
            // n = 4, score = 300
            //   32d1                 | xor                 dl, cl
            //   88143e               | mov                 byte ptr [esi + edi], dl
            //   8a4805               | mov                 cl, byte ptr [eax + 5]
            //   02ca                 | add                 cl, dl

        $sequence_4 = { 33c0 c3 05d13fffff 83f801 77f3 }
            // n = 5, score = 300
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   05d13fffff           | add                 eax, 0xffff3fd1
            //   83f801               | cmp                 eax, 1
            //   77f3                 | ja                  0xfffffff5

        $sequence_5 = { 3d9c000000 7c07 3d9f000000 7e0d }
            // n = 4, score = 300
            //   3d9c000000           | cmp                 eax, 0x9c
            //   7c07                 | jl                  9
            //   3d9f000000           | cmp                 eax, 0x9f
            //   7e0d                 | jle                 0xf

        $sequence_6 = { 0fbec3 83c40c 83f803 0f8781000000 }
            // n = 4, score = 300
            //   0fbec3               | movsx               eax, bl
            //   83c40c               | add                 esp, 0xc
            //   83f803               | cmp                 eax, 3
            //   0f8781000000         | ja                  0x87

        $sequence_7 = { 32ca ff4df0 880c3e 7590 46 3b7508 0f8c76ffffff }
            // n = 7, score = 300
            //   32ca                 | xor                 cl, dl
            //   ff4df0               | dec                 dword ptr [ebp - 0x10]
            //   880c3e               | mov                 byte ptr [esi + edi], cl
            //   7590                 | jne                 0xffffff92
            //   46                   | inc                 esi
            //   3b7508               | cmp                 esi, dword ptr [ebp + 8]
            //   0f8c76ffffff         | jl                  0xffffff7c

        $sequence_8 = { 3d2cc00000 7f18 3d2bc00000 7d1b 3d9c000000 7c07 }
            // n = 6, score = 300
            //   3d2cc00000           | cmp                 eax, 0xc02c
            //   7f18                 | jg                  0x1a
            //   3d2bc00000           | cmp                 eax, 0xc02b
            //   7d1b                 | jge                 0x1d
            //   3d9c000000           | cmp                 eax, 0x9c
            //   7c07                 | jl                  9

        $sequence_9 = { 33c0 eb1e a1???????? 8d5604 }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   eb1e                 | jmp                 0x20
            //   a1????????           |                     
            //   8d5604               | lea                 edx, [esi + 4]

        $sequence_10 = { 7305 83c303 eb1c 81fb00000100 }
            // n = 4, score = 300
            //   7305                 | jae                 7
            //   83c303               | add                 ebx, 3
            //   eb1c                 | jmp                 0x1e
            //   81fb00000100         | cmp                 ebx, 0x10000

        $sequence_11 = { 50 e8???????? 83c410 56 e8???????? 83c404 85c0 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax

        $sequence_12 = { 7305 83c302 eb29 81fb00010000 7305 }
            // n = 5, score = 300
            //   7305                 | jae                 7
            //   83c302               | add                 ebx, 2
            //   eb29                 | jmp                 0x2b
            //   81fb00010000         | cmp                 ebx, 0x100
            //   7305                 | jae                 7

        $sequence_13 = { 0fb713 668b4df0 6a06 6a01 52 }
            // n = 5, score = 300
            //   0fb713               | movzx               edx, word ptr [ebx]
            //   668b4df0             | mov                 cx, word ptr [ebp - 0x10]
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   52                   | push                edx

        $sequence_14 = { 3d9f000000 7e0d 33c0 c3 }
            // n = 4, score = 300
            //   3d9f000000           | cmp                 eax, 0x9f
            //   7e0d                 | jle                 0xf
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_15 = { 48 ba???????? 2bd0 83c2fe }
            // n = 4, score = 300
            //   48                   | dec                 eax
            //   ba????????           |                     
            //   2bd0                 | sub                 edx, eax
            //   83c2fe               | add                 edx, -2

    condition:
        7 of them and filesize < 1064960
}