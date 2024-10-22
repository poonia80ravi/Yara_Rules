rule win_op_blockbuster_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.op_blockbuster."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.op_blockbuster"
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
        $sequence_0 = { 8a08 80f920 7505 83c021 eb05 }
            // n = 5, score = 800
            //   8a08                 | pop                 edi
            //   80f920               | test                esi, esi
            //   7505                 | pop                 esi
            //   83c021               | push                esi
            //   eb05                 | push                edi

        $sequence_1 = { c701???????? 8b497c 85c9 7407 }
            // n = 4, score = 800
            //   c701????????         |                     
            //   8b497c               | inc                 esp
            //   85c9                 | movzx               eax, word ptr [esp + 0x30]
            //   7407                 | dec                 eax

        $sequence_2 = { e8???????? 33c9 5f 85c0 0f9fc1 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   33c9                 | add                 al, 9
            //   5f                   | mov                 dword ptr [esp + 0x20], 2
            //   85c0                 | test                eax, eax
            //   0f9fc1               | je                  0x7a

        $sequence_3 = { ff15???????? 6808400000 6a40 ff15???????? }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   6808400000           | pop                 edi
            //   6a40                 | test                eax, eax
            //   ff15????????         |                     

        $sequence_4 = { e8???????? 6800400000 6a00 ff15???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   6800400000           | lea                 edx, [esp + 0x40]
            //   6a00                 | dec                 esp
            //   ff15????????         |                     

        $sequence_5 = { aa 5f 85f6 5e }
            // n = 4, score = 800
            //   aa                   | jmp                 0xc
            //   5f                   | cmp                 al, 0x70
            //   85f6                 | jg                  8
            //   5e                   | add                 al, 9

        $sequence_6 = { 56 57 683c400000 6a40 }
            // n = 4, score = 800
            //   56                   | jl                  0xa
            //   57                   | cmp                 al, 0x70
            //   683c400000           | jg                  6
            //   6a40                 | add                 al, 9

        $sequence_7 = { 7412 68???????? 50 e8???????? 59 a3???????? 59 }
            // n = 7, score = 700
            //   7412                 | add                 esp, 0xc
            //   68????????           |                     
            //   50                   | ret                 
            //   e8????????           |                     
            //   59                   | test                eax, eax
            //   a3????????           |                     
            //   59                   | je                  7

        $sequence_8 = { 68???????? 56 ff15???????? 68???????? 56 a3???????? e8???????? }
            // n = 7, score = 700
            //   68????????           |                     
            //   56                   | pop                 esi
            //   ff15????????         |                     
            //   68????????           |                     
            //   56                   | mov                 cl, byte ptr [eax]
            //   a3????????           |                     
            //   e8????????           |                     

        $sequence_9 = { 56 50 8d45fc 6a04 50 }
            // n = 5, score = 700
            //   56                   | xor                 eax, eax
            //   50                   | lea                 edx, [esp + 0xc0c]
            //   8d45fc               | repne scasb         al, byte ptr es:[edi]
            //   6a04                 | not                 ecx
            //   50                   | stosw               word ptr es:[edi], ax

        $sequence_10 = { 3c70 7f04 0409 eb06 3c72 }
            // n = 5, score = 500
            //   3c70                 | cmp                 al, 0x70
            //   7f04                 | jg                  6
            //   0409                 | add                 al, 9
            //   eb06                 | jmp                 8
            //   3c72                 | cmp                 al, 0x72

        $sequence_11 = { 3c69 7c08 3c70 7f04 }
            // n = 4, score = 500
            //   3c69                 | cmp                 al, 0x69
            //   7c08                 | jl                  0xa
            //   3c70                 | cmp                 al, 0x70
            //   7f04                 | jg                  6

        $sequence_12 = { 8bf0 ff15???????? 85f6 7404 85c0 }
            // n = 5, score = 300
            //   8bf0                 | ret                 
            //   ff15????????         |                     
            //   85f6                 | push                esi
            //   7404                 | push                ebx
            //   85c0                 | push                1

        $sequence_13 = { c3 33c0 ebf8 53 33db 391d???????? 56 }
            // n = 7, score = 300
            //   c3                   | je                  0xb
            //   33c0                 | push                ecx
            //   ebf8                 | rep stosd           dword ptr es:[edi], eax
            //   53                   | stosw               word ptr es:[edi], ax
            //   33db                 | stosb               byte ptr es:[edi], al
            //   391d????????         |                     
            //   56                   | pop                 edi

        $sequence_14 = { 5e c3 68???????? ff15???????? 85c0 7412 68???????? }
            // n = 7, score = 300
            //   5e                   | pop                 ecx
            //   c3                   | pop                 ecx
            //   68????????           |                     
            //   ff15????????         |                     
            //   85c0                 | ret                 
            //   7412                 | push                eax
            //   68????????           |                     

        $sequence_15 = { 448bc3 33d2 b910040000 ff15???????? 4883f8ff 0f84c5000000 }
            // n = 6, score = 300
            //   448bc3               | je                  0x2e
            //   33d2                 | dec                 esp
            //   b910040000           | lea                 ecx, [esp + 0x70]
            //   ff15????????         |                     
            //   4883f8ff             | dec                 esp
            //   0f84c5000000         | lea                 eax, [esp + 0x78]

        $sequence_16 = { c744242003000000 ff15???????? 488bd8 4883f8ff 7425 4c8d4c2470 4c8d442478 }
            // n = 7, score = 300
            //   c744242003000000     | mov                 dword ptr [esp + 0x20], ebx
            //   ff15????????         |                     
            //   488bd8               | dec                 eax
            //   4883f8ff             | mov                 ecx, ebx
            //   7425                 | test                eax, eax
            //   4c8d4c2470           | je                  0xffffff8f
            //   4c8d442478           | mov                 dword ptr [esp + 0x20], 3

        $sequence_17 = { 488bcb 85c0 748d ff15???????? }
            // n = 4, score = 300
            //   488bcb               | inc                 ecx
            //   85c0                 | lea                 edx, [ecx + 8]
            //   748d                 | dec                 esp
            //   ff15????????         |                     

        $sequence_18 = { ff15???????? 8bc6 5f 5e c3 33c0 6a00 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   8bc6                 | jmp                 0xf
            //   5f                   | test                cl, cl
            //   5e                   | mov                 cl, byte ptr [eax]
            //   c3                   | cmp                 cl, 0x20
            //   33c0                 | jne                 0xa
            //   6a00                 | add                 eax, 0x21

        $sequence_19 = { 440f4fc0 48895c2420 ff15???????? 448b442448 }
            // n = 4, score = 300
            //   440f4fc0             | je                  0xc5
            //   48895c2420           | inc                 esp
            //   ff15????????         |                     
            //   448b442448           | movzx               eax, word ptr [esp + 0x30]

        $sequence_20 = { e8???????? 56 e8???????? 83c414 b801000000 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c414               | xor                 eax, eax
            //   b801000000           | jmp                 0xfffffffa

        $sequence_21 = { 56 6a00 ff15???????? 8bf8 85ff 7504 5f }
            // n = 7, score = 300
            //   56                   | xor                 eax, eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8bf8                 | cmp                 dword ptr [esp + 8], eax
            //   85ff                 | jmp                 0xfffffffa
            //   7504                 | push                ebx
            //   5f                   | xor                 ebx, ebx

        $sequence_22 = { 4c8d5c2440 4c8d442444 418d5108 4c895c2420 }
            // n = 4, score = 300
            //   4c8d5c2440           | dec                 esp
            //   4c8d442444           | lea                 ebx, [esp + 0x40]
            //   418d5108             | dec                 esp
            //   4c895c2420           | lea                 eax, [esp + 0x44]

        $sequence_23 = { 0f84bf000000 440fb7442430 488d942450010000 4c8bcf }
            // n = 4, score = 300
            //   0f84bf000000         | dec                 eax
            //   440fb7442430         | mov                 ebx, eax
            //   488d942450010000     | dec                 eax
            //   4c8bcf               | cmp                 eax, -1

        $sequence_24 = { c3 56 53 6a01 57 e8???????? 56 }
            // n = 7, score = 300
            //   c3                   | xor                 eax, eax
            //   56                   | push                0
            //   53                   | mov                 eax, esi
            //   6a01                 | pop                 edi
            //   57                   | pop                 esi
            //   e8????????           |                     
            //   56                   | ret                 

        $sequence_25 = { 6a40 ff74240c ff74240c e8???????? 83c40c c3 a1???????? }
            // n = 7, score = 200
            //   6a40                 | push                ebx
            //   ff74240c             | push                1
            //   ff74240c             | push                edi
            //   e8????????           |                     
            //   83c40c               | push                esi
            //   c3                   | add                 esp, 0x14
            //   a1????????           |                     

        $sequence_26 = { 0f879c000000 ff2485d60b4100 8bce e8???????? eb44 895e24 }
            // n = 6, score = 200
            //   0f879c000000         | push                esi
            //   ff2485d60b4100       | push                ebx
            //   8bce                 | push                1
            //   e8????????           |                     
            //   eb44                 | push                esi
            //   895e24               | add                 esp, 0x14

        $sequence_27 = { 83c40c c3 a1???????? 85c0 7402 ffd0 }
            // n = 6, score = 200
            //   83c40c               | add                 esp, 0x38
            //   c3                   | ret                 
            //   a1????????           |                     
            //   85c0                 | push                esi
            //   7402                 | push                ebx
            //   ffd0                 | push                1

        $sequence_28 = { 49 8945f8 8b45f0 894df4 8b0485d8974400 c644022c0a }
            // n = 6, score = 200
            //   49                   | push                edi
            //   8945f8               | test                esi, esi
            //   8b45f0               | je                  6
            //   894df4               | test                eax, eax
            //   8b0485d8974400       | push                edi
            //   c644022c0a           | push                esi

        $sequence_29 = { 660f59f5 660f28aaf0534400 660f54e5 660f58fe 660f58fc 660f59c8 }
            // n = 6, score = 200
            //   660f59f5             | push                ebx
            //   660f28aaf0534400     | push                1
            //   660f54e5             | push                edi
            //   660f58fe             | push                esi
            //   660f58fc             | add                 esp, 0x14
            //   660f59c8             | ret                 

        $sequence_30 = { c700???????? 8b4508 898850030000 8b4508 59 c7404840854400 }
            // n = 6, score = 200
            //   c700????????         |                     
            //   8b4508               | mov                 eax, 1
            //   898850030000         | ret                 
            //   8b4508               | push                esi
            //   59                   | push                ebx
            //   c7404840854400       | push                1

        $sequence_31 = { 83c8ff 3bf0 7420 8d4514 6a00 50 }
            // n = 6, score = 100
            //   83c8ff               | pop                 esi
            //   3bf0                 | ret                 
            //   7420                 | test                eax, eax
            //   8d4514               | pop                 esi
            //   6a00                 | ret                 
            //   50                   | test                eax, eax

        $sequence_32 = { 83e103 f3aa 2b5dfc 2b75f8 33ff 2b75fc }
            // n = 6, score = 100
            //   83e103               | push                eax
            //   f3aa                 | push                edi
            //   2b5dfc               | pop                 esi
            //   2b75f8               | ret                 
            //   33ff                 | test                eax, eax
            //   2b75fc               | je                  0x17

        $sequence_33 = { 8855bc 8d5dbc f3ab 8b7d0c 83c9ff f2ae f7d1 }
            // n = 7, score = 100
            //   8855bc               | lea                 eax, [ebp - 4]
            //   8d5dbc               | push                4
            //   f3ab                 | push                eax
            //   8b7d0c               | push                edi
            //   83c9ff               | push                eax
            //   f2ae                 | lea                 eax, [ebp - 4]
            //   f7d1                 | push                4

        $sequence_34 = { ff15???????? 8bc6 8d8de0fdffff 2bc1 d1f8 48 50 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bc6                 | je                  0x17
            //   8d8de0fdffff         | pop                 esi
            //   2bc1                 | ret                 
            //   d1f8                 | test                eax, eax
            //   48                   | je                  0x17
            //   50                   | mov                 byte ptr [ebp - 0x44], dl

    condition:
        7 of them and filesize < 74309632
}