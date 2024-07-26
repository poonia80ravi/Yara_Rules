rule win_sakula_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sakula_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sakula_rat"
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
        $sequence_0 = { 6a00 6800010000 6a00 6a00 68???????? }
            // n = 5, score = 300
            //   6a00                 | push                0
            //   6800010000           | push                0x100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_1 = { a1???????? 50 ff15???????? c705????????ffffffff 5f 32c0 }
            // n = 6, score = 200
            //   a1????????           |                     
            //   50                   | mov                 eax, edi
            //   ff15????????         |                     
            //   c705????????ffffffff     |     
            //   5f                   | add                 esp, 8
            //   32c0                 | cmp                 dword ptr [esi], 1

        $sequence_2 = { c1e902 f3a5 8bc8 83e103 8d8396000000 }
            // n = 5, score = 200
            //   c1e902               | mov                 eax, 3
            //   f3a5                 | jmp                 0x22
            //   8bc8                 | cmp                 eax, 1
            //   83e103               | jne                 0xc
            //   8d8396000000         | mov                 eax, 2

        $sequence_3 = { ff15???????? 6a00 ff15???????? cc 3b0d???????? 7502 f3c3 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   cc                   | inc                 eax
            //   3b0d????????         |                     
            //   7502                 | test                cl, cl
            //   f3c3                 | jne                 0xfffffff8

        $sequence_4 = { 8ad8 57 8bc7 e8???????? 83c408 833e01 }
            // n = 6, score = 200
            //   8ad8                 | xor                 ecx, ecx
            //   57                   | mov                 edi, eax
            //   8bc7                 | lea                 ebx, [eax + 4]
            //   e8????????           |                     
            //   83c408               | dec                 eax
            //   833e01               | test                eax, eax

        $sequence_5 = { 40 84c9 75f6 6a00 6880000000 6a02 }
            // n = 6, score = 200
            //   40                   | test                eax, eax
            //   84c9                 | je                  0xb6
            //   75f6                 | dec                 eax
            //   6a00                 | mov                 ecx, ebx
            //   6880000000           | and                 dword ptr [esp + 0x58], 0
            //   6a02                 | xor                 edx, edx

        $sequence_6 = { 51 6800900100 8d9614010000 52 50 }
            // n = 5, score = 200
            //   51                   | push                0
            //   6800900100           | push                0x80
            //   8d9614010000         | push                2
            //   52                   | mov                 bl, al
            //   50                   | push                edi

        $sequence_7 = { b803000000 eb1b e8???????? 83f801 7507 b802000000 eb0a }
            // n = 7, score = 200
            //   b803000000           | je                  0xdc
            //   eb1b                 | lea                 edi, [esi + 0x2f]
            //   e8????????           |                     
            //   83f801               | xor                 edx, edx
            //   7507                 | push                0
            //   b802000000           | push                0x100
            //   eb0a                 | push                0

        $sequence_8 = { 8b4508 83c00c ff30 8b4508 0514010000 50 ff35???????? }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c00c               | add                 eax, 0xc
            //   ff30                 | push                dword ptr [eax]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0514010000           | add                 eax, 0x114
            //   50                   | push                eax
            //   ff35????????         |                     

        $sequence_9 = { 8945d8 8945d4 8945d0 ff7508 e8???????? ff7508 }
            // n = 6, score = 100
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_10 = { ebec 8d040a 40 50 ff75f8 e8???????? 83c408 }
            // n = 7, score = 100
            //   ebec                 | jmp                 0xffffffee
            //   8d040a               | lea                 eax, [edx + ecx]
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_11 = { 33d2 488d4c2478 448d4260 e8???????? 33db 33c0 }
            // n = 6, score = 100
            //   33d2                 | mov                 eax, edi
            //   488d4c2478           | dec                 esp
            //   448d4260             | lea                 ecx, [ebp - 0x39]
            //   e8????????           |                     
            //   33db                 | dec                 esp
            //   33c0                 | lea                 eax, [0x1da0]

        $sequence_12 = { 488b4c2450 8d5340 ff15???????? 488b4c2458 8d53f1 }
            // n = 5, score = 100
            //   488b4c2450           | xor                 ebx, ebx
            //   8d5340               | xor                 eax, eax
            //   ff15????????         |                     
            //   488b4c2458           | dec                 eax
            //   8d53f1               | mov                 ecx, ebx

        $sequence_13 = { 8945fc 83f800 0f84db000000 8b5dfc e8???????? 8903 83c304 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   83f800               | cmp                 eax, 0
            //   0f84db000000         | je                  0xe1
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8903                 | mov                 dword ptr [ebx], eax
            //   83c304               | add                 ebx, 4

        $sequence_14 = { e8???????? 68f4010000 e8???????? ff75dc e8???????? c745dc00000000 8b45e8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68f4010000           | push                0x1f4
            //   e8????????           |                     
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   e8????????           |                     
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_15 = { 448bc7 488905???????? e8???????? 4c8d4dc7 4c8d05a01d0000 488d0da90e0000 }
            // n = 6, score = 100
            //   448bc7               | dec                 eax
            //   488905????????       |                     
            //   e8????????           |                     
            //   4c8d4dc7             | mov                 ecx, eax
            //   4c8d05a01d0000       | test                eax, eax
            //   488d0da90e0000       | inc                 esp

        $sequence_16 = { 488bcb ff15???????? 8364245800 ff15???????? 488d542458 488bc8 }
            // n = 6, score = 100
            //   488bcb               | dec                 eax
            //   ff15????????         |                     
            //   8364245800           | lea                 ecx, [0xea9]
            //   ff15????????         |                     
            //   488d542458           | xor                 edx, edx
            //   488bc8               | dec                 eax

        $sequence_17 = { ff15???????? ff15???????? 83f801 0f85ed000000 4c8d05250e0000 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   83f801               | lea                 ecx, [esp + 0x78]
            //   0f85ed000000         | inc                 esp
            //   4c8d05250e0000       | lea                 eax, [edx + 0x60]

        $sequence_18 = { 488bd8 4885c0 0f84bf000000 488bc8 ff15???????? 85c0 }
            // n = 6, score = 100
            //   488bd8               | dec                 eax
            //   4885c0               | mov                 ebx, eax
            //   0f84bf000000         | dec                 eax
            //   488bc8               | test                eax, eax
            //   ff15????????         |                     
            //   85c0                 | je                  0xc8

        $sequence_19 = { 33d2 33c9 ff15???????? 8bf8 8d5804 ff15???????? }
            // n = 6, score = 100
            //   33d2                 | cmp                 eax, 1
            //   33c9                 | jne                 0xf6
            //   ff15????????         |                     
            //   8bf8                 | dec                 esp
            //   8d5804               | lea                 eax, [0xe25]
            //   ff15????????         |                     

        $sequence_20 = { 743d 8945d8 6a01 e8???????? 6a00 8d45dc }
            // n = 6, score = 100
            //   743d                 | je                  0x3f
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   6a01                 | push                1
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d45dc               | lea                 eax, [ebp - 0x24]

        $sequence_21 = { 488bc8 ff15???????? 85c0 0f84ae000000 488bcb ff15???????? 8364245800 }
            // n = 7, score = 100
            //   488bc8               | and                 dword ptr [esp + 0x58], 0
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   0f84ae000000         | lea                 edx, [esp + 0x58]
            //   488bcb               | dec                 eax
            //   ff15????????         |                     
            //   8364245800           | mov                 ecx, eax

        $sequence_22 = { eb02 31c0 bb???????? 8903 5a }
            // n = 5, score = 100
            //   eb02                 | jmp                 4
            //   31c0                 | xor                 eax, eax
            //   bb????????           |                     
            //   8903                 | mov                 dword ptr [ebx], eax
            //   5a                   | pop                 edx

    condition:
        7 of them and filesize < 229376
}