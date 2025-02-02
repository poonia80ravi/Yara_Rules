rule win_xtunnel_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.xtunnel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xtunnel"
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
        $sequence_0 = { 8d4afe 89442410 89442414 8954241c 3bf1 0f8379040000 0fb606 }
            // n = 7, score = 1200
            //   8d4afe               | lea                 ecx, [edx - 2]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx
            //   3bf1                 | cmp                 esi, ecx
            //   0f8379040000         | jae                 0x47f
            //   0fb606               | movzx               eax, byte ptr [esi]

        $sequence_1 = { 8d9c2490000000 894110 83c410 8d4b01 8a03 43 }
            // n = 6, score = 1200
            //   8d9c2490000000       | lea                 ebx, [esp + 0x90]
            //   894110               | mov                 dword ptr [ecx + 0x10], eax
            //   83c410               | add                 esp, 0x10
            //   8d4b01               | lea                 ecx, [ebx + 1]
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   43                   | inc                 ebx

        $sequence_2 = { 8b11 83c202 52 e8???????? }
            // n = 4, score = 1200
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   83c202               | add                 edx, 2
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_3 = { eb6d ba01ff0000 663bda 7522 8b442434 }
            // n = 5, score = 1200
            //   eb6d                 | jmp                 0x6f
            //   ba01ff0000           | mov                 edx, 0xff01
            //   663bda               | cmp                 bx, dx
            //   7522                 | jne                 0x24
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]

        $sequence_4 = { 8d440702 83c602 89442414 3bc3 0f879e000000 57 8d54241c }
            // n = 7, score = 1200
            //   8d440702             | lea                 eax, [edi + eax + 2]
            //   83c602               | add                 esi, 2
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   3bc3                 | cmp                 eax, ebx
            //   0f879e000000         | ja                  0xa4
            //   57                   | push                edi
            //   8d54241c             | lea                 edx, [esp + 0x1c]

        $sequence_5 = { 8b90e4000000 53 56 52 e8???????? }
            // n = 5, score = 1200
            //   8b90e4000000         | mov                 edx, dword ptr [eax + 0xe4]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_6 = { 8bcf 2bcb 2bc8 83e905 0f8876060000 }
            // n = 5, score = 1200
            //   8bcf                 | mov                 ecx, edi
            //   2bcb                 | sub                 ecx, ebx
            //   2bc8                 | sub                 ecx, eax
            //   83e905               | sub                 ecx, 5
            //   0f8876060000         | js                  0x67c

        $sequence_7 = { e8???????? 99 b960000000 f7f9 }
            // n = 4, score = 1200
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b960000000           | mov                 ecx, 0x60
            //   f7f9                 | idiv                ecx

        $sequence_8 = { 8bd8 3d00110000 7f55 741c 83e803 0f84d5050000 }
            // n = 6, score = 1200
            //   8bd8                 | mov                 ebx, eax
            //   3d00110000           | cmp                 eax, 0x1100
            //   7f55                 | jg                  0x57
            //   741c                 | je                  0x1e
            //   83e803               | sub                 eax, 3
            //   0f84d5050000         | je                  0x5db

        $sequence_9 = { 8bcf 2bc8 83e906 0f8833050000 }
            // n = 4, score = 1200
            //   8bcf                 | mov                 ecx, edi
            //   2bc8                 | sub                 ecx, eax
            //   83e906               | sub                 ecx, 6
            //   0f8833050000         | js                  0x539

        $sequence_10 = { c7010c000000 5e 5d c3 6a00 }
            // n = 5, score = 1100
            //   c7010c000000         | mov                 dword ptr [ecx], 0xc
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a00                 | push                0

        $sequence_11 = { 0fb7560a 6689500a 8b4e0c 89480c }
            // n = 4, score = 1000
            //   0fb7560a             | movzx               edx, word ptr [esi + 0xa]
            //   6689500a             | mov                 word ptr [eax + 0xa], dx
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx

        $sequence_12 = { 740a 8b450c e8???????? 8bd8 }
            // n = 4, score = 1000
            //   740a                 | je                  0xc
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_13 = { 0fb75108 66895008 8b5118 895018 }
            // n = 4, score = 1000
            //   0fb75108             | movzx               edx, word ptr [ecx + 8]
            //   66895008             | mov                 word ptr [eax + 8], dx
            //   8b5118               | mov                 edx, dword ptr [ecx + 0x18]
            //   895018               | mov                 dword ptr [eax + 0x18], edx

        $sequence_14 = { e8???????? 8918 8d550c 8d4740 89750c }
            // n = 5, score = 1000
            //   e8????????           |                     
            //   8918                 | mov                 dword ptr [eax], ebx
            //   8d550c               | lea                 edx, [ebp + 0xc]
            //   8d4740               | lea                 eax, [edi + 0x40]
            //   89750c               | mov                 dword ptr [ebp + 0xc], esi

        $sequence_15 = { e8???????? 8b5b04 53 e8???????? 8d5f20 83c404 }
            // n = 6, score = 1000
            //   e8????????           |                     
            //   8b5b04               | mov                 ebx, dword ptr [ebx + 4]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d5f20               | lea                 ebx, [edi + 0x20]
            //   83c404               | add                 esp, 4

        $sequence_16 = { 83c404 3bc3 743a 8b4e04 }
            // n = 4, score = 1000
            //   83c404               | add                 esp, 4
            //   3bc3                 | cmp                 eax, ebx
            //   743a                 | je                  0x3c
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]

        $sequence_17 = { e8???????? 83c404 33c9 8bc6 }
            // n = 4, score = 1000
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c9                 | xor                 ecx, ecx
            //   8bc6                 | mov                 eax, esi

        $sequence_18 = { 751c 8d642400 39500c 7d05 }
            // n = 4, score = 1000
            //   751c                 | jne                 0x1e
            //   8d642400             | lea                 esp, [esp]
            //   39500c               | cmp                 dword ptr [eax + 0xc], edx
            //   7d05                 | jge                 7

        $sequence_19 = { 83c404 8945b0 8b45b4 50 6a00 }
            // n = 5, score = 500
            //   83c404               | add                 esp, 4
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_20 = { c685c5f0ffffbb c685c6f0ffff81 c685c7f0ffff2a c685c8f0ffff2a }
            // n = 4, score = 300
            //   c685c5f0ffffbb       | mov                 byte ptr [ebp - 0xf3b], 0xbb
            //   c685c6f0ffff81       | mov                 byte ptr [ebp - 0xf3a], 0x81
            //   c685c7f0ffff2a       | mov                 byte ptr [ebp - 0xf39], 0x2a
            //   c685c8f0ffff2a       | mov                 byte ptr [ebp - 0xf38], 0x2a

        $sequence_21 = { c685c5efffff3d c685c6efffff66 c685c7efffff32 c685c8efffff28 }
            // n = 4, score = 300
            //   c685c5efffff3d       | mov                 byte ptr [ebp - 0x103b], 0x3d
            //   c685c6efffff66       | mov                 byte ptr [ebp - 0x103a], 0x66
            //   c685c7efffff32       | mov                 byte ptr [ebp - 0x1039], 0x32
            //   c685c8efffff28       | mov                 byte ptr [ebp - 0x1038], 0x28

        $sequence_22 = { c685c5f2ffffcb c685c6f2ffff12 c685c7f2ffff67 c685c8f2ffffd2 }
            // n = 4, score = 300
            //   c685c5f2ffffcb       | mov                 byte ptr [ebp - 0xd3b], 0xcb
            //   c685c6f2ffff12       | mov                 byte ptr [ebp - 0xd3a], 0x12
            //   c685c7f2ffff67       | mov                 byte ptr [ebp - 0xd39], 0x67
            //   c685c8f2ffffd2       | mov                 byte ptr [ebp - 0xd38], 0xd2

        $sequence_23 = { c685c5f1ffffea c685c6f1ffff82 c685c7f1ffff32 c685c8f1ffffe8 }
            // n = 4, score = 300
            //   c685c5f1ffffea       | mov                 byte ptr [ebp - 0xe3b], 0xea
            //   c685c6f1ffff82       | mov                 byte ptr [ebp - 0xe3a], 0x82
            //   c685c7f1ffff32       | mov                 byte ptr [ebp - 0xe39], 0x32
            //   c685c8f1ffffe8       | mov                 byte ptr [ebp - 0xe38], 0xe8

    condition:
        7 of them and filesize < 4634440
}