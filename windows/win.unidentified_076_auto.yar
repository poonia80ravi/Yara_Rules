rule win_unidentified_076_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_076."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_076"
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
        $sequence_0 = { 44899368130000 488b8340130000 b905000000 3908 7d26 8908 eb2d }
            // n = 7, score = 100
            //   44899368130000       | je                  0x1c38
            //   488b8340130000       | dec                 eax
            //   b905000000           | mov                 eax, dword ptr [ebx + 0xc8]
            //   3908                 | dec                 eax
            //   7d26                 | test                eax, eax
            //   8908                 | je                  0x1c38
            //   eb2d                 | dec                 eax

        $sequence_1 = { 498bcf ff9020070000 488b86c8000000 4c8b842488000000 488d9644090000 498bcf ff90e0070000 }
            // n = 7, score = 100
            //   498bcf               | dec                 eax
            //   ff9020070000         | mov                 edi, ecx
            //   488b86c8000000       | dec                 ecx
            //   4c8b842488000000     | cmp                 dword ptr [eax], ebx
            //   488d9644090000       | je                  0x1f72
            //   498bcf               | dec                 eax
            //   ff90e0070000         | mov                 eax, dword ptr [ecx + 0xc8]

        $sequence_2 = { 498bce 4489441830 89541834 448b85d0000000 4181c070130000 488bd3 }
            // n = 6, score = 100
            //   498bce               | xor                 ecx, ecx
            //   4489441830           | inc                 ecx
            //   89541834             | mov                 eax, 0x1000
            //   448b85d0000000       | inc                 esp
            //   4181c070130000       | lea                 ecx, [ecx + 4]
            //   488bd3               | inc                 ecx

        $sequence_3 = { 4c8bf8 4885c0 74de 458bce 448bc5 ba00040000 33c9 }
            // n = 7, score = 100
            //   4c8bf8               | add                 esp, 0x20
            //   4885c0               | inc                 ecx
            //   74de                 | pop                 esi
            //   458bce               | pop                 edi
            //   448bc5               | imul                ecx, dword ptr [eax], 0x3e8
            //   ba00040000           | call                dword ptr [edx + 0x10]
            //   33c9                 | cmp                 dword ptr [ebx + 0x2d4], 1

        $sequence_4 = { e9???????? 488b83c8000000 488b8be8010000 33d2 41b805140000 ff9020070000 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   488b83c8000000       | dec                 eax
            //   488b8be8010000       | mov                 ecx, esi
            //   33d2                 | dec                 eax
            //   41b805140000         | mov                 edi, dword ptr [esi + 0xc8]
            //   ff9020070000         | dec                 esp

        $sequence_5 = { 803c313b 740c 48ffc1 ffc2 493bc8 7cf0 eb17 }
            // n = 7, score = 100
            //   803c313b             | mov                 esi, dword ptr [esp + 0x70]
            //   740c                 | dec                 eax
            //   48ffc1               | mov                 edi, dword ptr [esp + 0x78]
            //   ffc2                 | mov                 eax, ebx
            //   493bc8               | mov                 dword ptr [edi + 0x2d0], ebp
            //   7cf0                 | mov                 ebx, ebp
            //   eb17                 | inc                 ecx

        $sequence_6 = { 4d8bc7 33d2 41ff9120070000 488b742458 488b7c2460 4c8b742468 8bc3 }
            // n = 7, score = 100
            //   4d8bc7               | mov                 edi, esi
            //   33d2                 | jmp                 0x898
            //   41ff9120070000       | inc                 ecx
            //   488b742458           | mov                 ecx, 6
            //   488b7c2460           | jmp                 0x878
            //   4c8b742468           | inc                 ecx
            //   8bc3                 | mov                 ecx, 5

        $sequence_7 = { 4d8bc4 488bd6 ff9040070000 488b83c8000000 488d8c2450010000 c744243068000000 48894c2428 }
            // n = 7, score = 100
            //   4d8bc4               | dec                 eax
            //   488bd6               | mov                 edx, esi
            //   ff9040070000         | call                dword ptr [eax + 0x740]
            //   488b83c8000000       | jl                  0x721
            //   488d8c2450010000     | inc                 ecx
            //   c744243068000000     | movzx               ecx, cx
            //   48894c2428           | inc                 ecx

        $sequence_8 = { ff90f0070000 488b83c8000000 b9e8030000 ff5010 e9???????? }
            // n = 5, score = 100
            //   ff90f0070000         | mov                 ecx, esi
            //   488b83c8000000       | dec                 eax
            //   b9e8030000           | mov                 eax, dword ptr [ecx + 0xc8]
            //   ff5010               | dec                 esp
            //   e9????????           |                     

        $sequence_9 = { 4533c9 448bc3 498bd7 498bcc ff90b0030000 }
            // n = 5, score = 100
            //   4533c9               | add                 ecx, 5
            //   448bc3               | test                edx, eax
            //   498bd7               | je                  0x531
            //   498bcc               | lea                 eax, [ecx - 1]
            //   ff90b0030000         | cmp                 eax, 2

    condition:
        7 of them and filesize < 114688
}