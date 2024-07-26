rule win_9002_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.9002."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.9002"
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
        $sequence_0 = { 50 e8???????? 83c408 894604 03c5 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   03c5                 | add                 eax, ebp

        $sequence_1 = { 6bdb08 03c3 8b00 5b }
            // n = 4, score = 200
            //   6bdb08               | imul                ebx, ebx, 8
            //   03c3                 | add                 eax, ebx
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   5b                   | pop                 ebx

        $sequence_2 = { 8b461c 85c0 7424 682c010000 }
            // n = 4, score = 200
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   85c0                 | test                eax, eax
            //   7424                 | je                  0x26
            //   682c010000           | push                0x12c

        $sequence_3 = { 6a00 6a02 6a03 6a00 e8???????? }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_4 = { 51 e8???????? 6a06 6a01 6a02 e8???????? }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_5 = { 33ed eb04 2bc8 8be9 53 50 }
            // n = 6, score = 200
            //   33ed                 | xor                 ebp, ebp
            //   eb04                 | jmp                 6
            //   2bc8                 | sub                 ecx, eax
            //   8be9                 | mov                 ebp, ecx
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_6 = { 6a02 ff15???????? 68???????? ff15???????? 6a00 }
            // n = 5, score = 200
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_7 = { 6a00 51 8944241c c744241801000000 ff15???????? 3d02010000 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   c744241801000000     | mov                 dword ptr [esp + 0x18], 1
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102

        $sequence_8 = { 8b00 5b ffd0 59 }
            // n = 4, score = 200
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   5b                   | pop                 ebx
            //   ffd0                 | call                eax
            //   59                   | pop                 ecx

        $sequence_9 = { 8bc2 2d00040000 f7d8 1bc0 }
            // n = 4, score = 200
            //   8bc2                 | mov                 eax, edx
            //   2d00040000           | sub                 eax, 0x400
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax

        $sequence_10 = { 33c9 3bc8 1bd2 f7da 8915???????? }
            // n = 5, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   3bc8                 | cmp                 ecx, eax
            //   1bd2                 | sbb                 edx, edx
            //   f7da                 | neg                 edx
            //   8915????????         |                     

        $sequence_11 = { 33db eb04 8bd9 2bd8 }
            // n = 4, score = 200
            //   33db                 | xor                 ebx, ebx
            //   eb04                 | jmp                 6
            //   8bd9                 | mov                 ebx, ecx
            //   2bd8                 | sub                 ebx, eax

        $sequence_12 = { 6a00 ffd5 8906 83c604 }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   ffd5                 | call                ebp
            //   8906                 | mov                 dword ptr [esi], eax
            //   83c604               | add                 esi, 4

        $sequence_13 = { 8b4714 8b08 51 e8???????? 8b5714 }
            // n = 5, score = 200
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b5714               | mov                 edx, dword ptr [edi + 0x14]

        $sequence_14 = { 8bc3 c1f805 8d3c85e0d50010 8bc3 83e01f 8d34c0 }
            // n = 6, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   c1f805               | sar                 eax, 5
            //   8d3c85e0d50010       | lea                 edi, [eax*4 + 0x1000d5e0]
            //   8bc3                 | mov                 eax, ebx
            //   83e01f               | and                 eax, 0x1f
            //   8d34c0               | lea                 esi, [eax + eax*8]

        $sequence_15 = { 50 ff15???????? 85c0 0f8499000000 833c2402 0f8c8f000000 8b4004 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8499000000         | je                  0x9f
            //   833c2402             | cmp                 dword ptr [esp], 2
            //   0f8c8f000000         | jl                  0x95
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_16 = { 33c4 50 8d442414 64a300000000 8bf1 e8???????? 8be8 }
            // n = 7, score = 100
            //   33c4                 | xor                 eax, esp
            //   50                   | push                eax
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8be8                 | mov                 ebp, eax

        $sequence_17 = { 33ff 3d00000001 895c2454 668b3b }
            // n = 4, score = 100
            //   33ff                 | xor                 edi, edi
            //   3d00000001           | cmp                 eax, 0x1000000
            //   895c2454             | mov                 dword ptr [esp + 0x54], ebx
            //   668b3b               | mov                 di, word ptr [ebx]

        $sequence_18 = { 0311 8955fc 837df800 0f86e3000000 8b4508 03450c 2b45f8 }
            // n = 7, score = 100
            //   0311                 | add                 edx, dword ptr [ecx]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   0f86e3000000         | jbe                 0xe9
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   03450c               | add                 eax, dword ptr [ebp + 0xc]
            //   2b45f8               | sub                 eax, dword ptr [ebp - 8]

        $sequence_19 = { 8d44242c 64a300000000 8bf1 8b4604 85c0 0f8593000000 68???????? }
            // n = 7, score = 100
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf1                 | mov                 esi, ecx
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax
            //   0f8593000000         | jne                 0x99
            //   68????????           |                     

        $sequence_20 = { 03fb 81f900000001 8bd1 668b2c78 732f 8b542428 8b7c2424 }
            // n = 7, score = 100
            //   03fb                 | add                 edi, ebx
            //   81f900000001         | cmp                 ecx, 0x1000000
            //   8bd1                 | mov                 edx, ecx
            //   668b2c78             | mov                 bp, word ptr [eax + edi*2]
            //   732f                 | jae                 0x31
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]

        $sequence_21 = { 031481 52 8b450c 50 }
            // n = 4, score = 100
            //   031481               | add                 edx, dword ptr [ecx + eax*4]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax

        $sequence_22 = { 8939 89742410 e9???????? 33f6 83ff14 7314 3b742410 }
            // n = 7, score = 100
            //   8939                 | mov                 dword ptr [ecx], edi
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   e9????????           |                     
            //   33f6                 | xor                 esi, esi
            //   83ff14               | cmp                 edi, 0x14
            //   7314                 | jae                 0x16
            //   3b742410             | cmp                 esi, dword ptr [esp + 0x10]

        $sequence_23 = { 668bac78b0010000 732b 8b442428 8b4c2424 3bc1 }
            // n = 5, score = 100
            //   668bac78b0010000     | mov                 bp, word ptr [eax + edi*2 + 0x1b0]
            //   732b                 | jae                 0x2d
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   3bc1                 | cmp                 eax, ecx

        $sequence_24 = { 50 ff15???????? 8b4e10 51 ff15???????? 897e10 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   897e10               | mov                 dword ptr [esi + 0x10], edi

        $sequence_25 = { 668bac78c8010000 732d 8b4c2424 8b7c2428 }
            // n = 4, score = 100
            //   668bac78c8010000     | mov                 bp, word ptr [eax + edi*2 + 0x1c8]
            //   732d                 | jae                 0x2f
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   8b7c2428             | mov                 edi, dword ptr [esp + 0x28]

        $sequence_26 = { c3 8b44240c 33c9 33d2 8a6804 }
            // n = 5, score = 100
            //   c3                   | ret                 
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   33c9                 | xor                 ecx, ecx
            //   33d2                 | xor                 edx, edx
            //   8a6804               | mov                 ch, byte ptr [eax + 4]

        $sequence_27 = { 0be9 8b7c2448 8b4c2454 d1e7 }
            // n = 4, score = 100
            //   0be9                 | or                  ebp, ecx
            //   8b7c2448             | mov                 edi, dword ptr [esp + 0x48]
            //   8b4c2454             | mov                 ecx, dword ptr [esp + 0x54]
            //   d1e7                 | shl                 edi, 1

        $sequence_28 = { 8b5604 85d2 7407 8b4104 03c2 }
            // n = 5, score = 100
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   85d2                 | test                edx, edx
            //   7407                 | je                  9
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   03c2                 | add                 eax, edx

        $sequence_29 = { 394f0c 7540 8b5748 807f040a 53 8b5a08 }
            // n = 6, score = 100
            //   394f0c               | cmp                 dword ptr [edi + 0xc], ecx
            //   7540                 | jne                 0x42
            //   8b5748               | mov                 edx, dword ptr [edi + 0x48]
            //   807f040a             | cmp                 byte ptr [edi + 4], 0xa
            //   53                   | push                ebx
            //   8b5a08               | mov                 ebx, dword ptr [edx + 8]

        $sequence_30 = { 895714 85f6 0f8486000000 8bce e8???????? }
            // n = 5, score = 100
            //   895714               | mov                 dword ptr [edi + 0x14], edx
            //   85f6                 | test                esi, esi
            //   0f8486000000         | je                  0x8c
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_31 = { 56 8b742408 57 85f6 742e 0fb74602 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   57                   | push                edi
            //   85f6                 | test                esi, esi
            //   742e                 | je                  0x30
            //   0fb74602             | movzx               eax, word ptr [esi + 2]

    condition:
        7 of them and filesize < 204800
}