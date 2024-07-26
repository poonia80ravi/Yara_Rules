rule win_sathurbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sathurbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sathurbot"
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
        $sequence_0 = { b8ece62ba8 e9???????? 3d804a7b11 7f3d 3d10de6d0d 0f8556fdffff a1???????? }
            // n = 7, score = 100
            //   b8ece62ba8           | mov                 eax, 0xa82be6ec
            //   e9????????           |                     
            //   3d804a7b11           | cmp                 eax, 0x117b4a80
            //   7f3d                 | jg                  0x3f
            //   3d10de6d0d           | cmp                 eax, 0xd6dde10
            //   0f8556fdffff         | jne                 0xfffffd5c
            //   a1????????           |                     

        $sequence_1 = { ebc1 c701ffffffff bee6b689a8 ebb4 ebfe 89c8 83c402 }
            // n = 7, score = 100
            //   ebc1                 | jmp                 0xffffffc3
            //   c701ffffffff         | mov                 dword ptr [ecx], 0xffffffff
            //   bee6b689a8           | mov                 esi, 0xa889b6e6
            //   ebb4                 | jmp                 0xffffffb6
            //   ebfe                 | jmp                 0
            //   89c8                 | mov                 eax, ecx
            //   83c402               | add                 esp, 2

        $sequence_2 = { ebc0 81f92000f7c3 7f33 81f94abc91b7 75b0 8b0d???????? 8d51ff }
            // n = 7, score = 100
            //   ebc0                 | jmp                 0xffffffc2
            //   81f92000f7c3         | cmp                 ecx, 0xc3f70020
            //   7f33                 | jg                  0x35
            //   81f94abc91b7         | cmp                 ecx, 0xb791bc4a
            //   75b0                 | jne                 0xffffffb2
            //   8b0d????????         |                     
            //   8d51ff               | lea                 edx, [ecx - 1]

        $sequence_3 = { f6c501 b94518f1a4 be7b8ee8a3 0f45ce e9???????? 81fea6600c29 89f1 }
            // n = 7, score = 100
            //   f6c501               | test                ch, 1
            //   b94518f1a4           | mov                 ecx, 0xa4f11845
            //   be7b8ee8a3           | mov                 esi, 0xa3e88e7b
            //   0f45ce               | cmovne              ecx, esi
            //   e9????????           |                     
            //   81fea6600c29         | cmp                 esi, 0x290c60a6
            //   89f1                 | mov                 ecx, esi

        $sequence_4 = { ebfe 8b4d0c e8???????? 88c3 c744240400000000 c7042401000000 8d4c2424 }
            // n = 7, score = 100
            //   ebfe                 | jmp                 0
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   88c3                 | mov                 bl, al
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   c7042401000000       | mov                 dword ptr [esp], 1
            //   8d4c2424             | lea                 ecx, [esp + 0x24]

        $sequence_5 = { b94fa22b60 0f45c1 e9???????? 3d87c78646 0f85fff5ffff 8b442478 8b4d14 }
            // n = 7, score = 100
            //   b94fa22b60           | mov                 ecx, 0x602ba24f
            //   0f45c1               | cmovne              eax, ecx
            //   e9????????           |                     
            //   3d87c78646           | cmp                 eax, 0x4686c787
            //   0f85fff5ffff         | jne                 0xfffff605
            //   8b442478             | mov                 eax, dword ptr [esp + 0x78]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]

        $sequence_6 = { eb15 8b442438 890424 ff15???????? 83ec04 b844b6fa84 3d669419dd }
            // n = 7, score = 100
            //   eb15                 | jmp                 0x17
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   890424               | mov                 dword ptr [esp], eax
            //   ff15????????         |                     
            //   83ec04               | sub                 esp, 4
            //   b844b6fa84           | mov                 eax, 0x84fab644
            //   3d669419dd           | cmp                 eax, 0xdd199466

        $sequence_7 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b8c1bed9bd b9d7e7524b }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b8c1bed9bd           | mov                 eax, 0xbdd9bec1
            //   b9d7e7524b           | mov                 ecx, 0x4b52e7d7

        $sequence_8 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b87a79be99 b9330fabc2 }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b87a79be99           | mov                 eax, 0x99be797a
            //   b9330fabc2           | mov                 ecx, 0xc2ab0f33

        $sequence_9 = { eb13 8a5df6 8a7df7 08df f6c701 be9334e765 0f45f0 }
            // n = 7, score = 100
            //   eb13                 | jmp                 0x15
            //   8a5df6               | mov                 bl, byte ptr [ebp - 0xa]
            //   8a7df7               | mov                 bh, byte ptr [ebp - 9]
            //   08df                 | or                  bh, bl
            //   f6c701               | test                bh, 1
            //   be9334e765           | mov                 esi, 0x65e73493
            //   0f45f0               | cmovne              esi, eax

    condition:
        7 of them and filesize < 2727936
}