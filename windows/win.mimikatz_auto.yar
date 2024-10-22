rule win_mimikatz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mimikatz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz"
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
        $sequence_0 = { 83f8ff 750e ff15???????? c7002a000000 }
            // n = 4, score = 300
            //   83f8ff               | cmp                 eax, -1
            //   750e                 | jne                 0x10
            //   ff15????????         |                     
            //   c7002a000000         | mov                 dword ptr [eax], 0x2a

        $sequence_1 = { f7f1 85d2 7406 2bca }
            // n = 4, score = 300
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx
            //   7406                 | je                  8
            //   2bca                 | sub                 ecx, edx

        $sequence_2 = { 83f812 72f1 33c0 c3 }
            // n = 4, score = 200
            //   83f812               | cmp                 eax, 0x12
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_3 = { e8???????? 85c0 0f8457010000 8b4d28 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8457010000         | je                  0x15d
            //   8b4d28               | mov                 ecx, dword ptr [ebp + 0x28]

        $sequence_4 = { 2bc1 85c9 7403 83c008 d1e8 8d441002 }
            // n = 6, score = 200
            //   2bc1                 | sub                 eax, ecx
            //   85c9                 | test                ecx, ecx
            //   7403                 | je                  5
            //   83c008               | add                 eax, 8
            //   d1e8                 | shr                 eax, 1
            //   8d441002             | lea                 eax, [eax + edx + 2]

        $sequence_5 = { ff15???????? 3bc3 7405 bb01000000 8bc3 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   7405                 | je                  7
            //   bb01000000           | mov                 ebx, 1
            //   8bc3                 | mov                 eax, ebx

        $sequence_6 = { 66894108 33c0 39410c 740b }
            // n = 4, score = 200
            //   66894108             | mov                 word ptr [ecx + 8], ax
            //   33c0                 | xor                 eax, eax
            //   39410c               | cmp                 dword ptr [ecx + 0xc], eax
            //   740b                 | je                  0xd

        $sequence_7 = { c3 81f998000000 7410 81f996000000 7408 }
            // n = 5, score = 200
            //   c3                   | ret                 
            //   81f998000000         | cmp                 ecx, 0x98
            //   7410                 | je                  0x12
            //   81f996000000         | cmp                 ecx, 0x96
            //   7408                 | je                  0xa

        $sequence_8 = { e8???????? 8b8b88000000 e8???????? 85ff }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8b8b88000000         | mov                 ecx, dword ptr [ebx + 0x88]
            //   e8????????           |                     
            //   85ff                 | test                edi, edi

        $sequence_9 = { ff15???????? b940000000 8bd0 89442430 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   b940000000           | mov                 ecx, 0x40
            //   8bd0                 | mov                 edx, eax
            //   89442430             | mov                 dword ptr [esp + 0x30], eax

        $sequence_10 = { 6683f83f 7607 32c0 e9???????? }
            // n = 4, score = 200
            //   6683f83f             | cmp                 ax, 0x3f
            //   7607                 | jbe                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_11 = { e9???????? 83fd70 0f8422020000 83fd73 0f8476010000 83fd75 0f8424020000 }
            // n = 7, score = 200
            //   e9????????           |                     
            //   83fd70               | cmp                 ebp, 0x70
            //   0f8422020000         | je                  0x228
            //   83fd73               | cmp                 ebp, 0x73
            //   0f8476010000         | je                  0x17c
            //   83fd75               | cmp                 ebp, 0x75
            //   0f8424020000         | je                  0x22a

        $sequence_12 = { 3c02 7207 e8???????? eb10 }
            // n = 4, score = 200
            //   3c02                 | cmp                 al, 2
            //   7207                 | jb                  9
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12

        $sequence_13 = { e8???????? ebb3 884c2439 bb02000000 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   ebb3                 | jmp                 0xffffffb5
            //   884c2439             | mov                 byte ptr [esp + 0x39], cl
            //   bb02000000           | mov                 ebx, 2

        $sequence_14 = { 8b4508 56 8d34c530d94600 833e00 7513 }
            // n = 5, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8d34c530d94600       | lea                 esi, [eax*8 + 0x46d930]
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7513                 | jne                 0x15

        $sequence_15 = { 4a 81ca00ffffff 42 0fb692b0e74600 321437 46 }
            // n = 6, score = 100
            //   4a                   | dec                 edx
            //   81ca00ffffff         | or                  edx, 0xffffff00
            //   42                   | inc                 edx
            //   0fb692b0e74600       | movzx               edx, byte ptr [edx + 0x46e7b0]
            //   321437               | xor                 dl, byte ptr [edi + esi]
            //   46                   | inc                 esi

        $sequence_16 = { 8b4508 ba???????? 2aca 884c05f8 }
            // n = 4, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ba????????           |                     
            //   2aca                 | sub                 cl, dl
            //   884c05f8             | mov                 byte ptr [ebp + eax - 8], cl

        $sequence_17 = { 6a0d 58 5d c3 8b04cd0cd04600 5d c3 }
            // n = 7, score = 100
            //   6a0d                 | push                0xd
            //   58                   | pop                 eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04cd0cd04600       | mov                 eax, dword ptr [ecx*8 + 0x46d00c]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_18 = { ff2495a0584000 8bc7 ba03000000 83e904 720c 83e003 }
            // n = 6, score = 100
            //   ff2495a0584000       | jmp                 dword ptr [edx*4 + 0x4058a0]
            //   8bc7                 | mov                 eax, edi
            //   ba03000000           | mov                 edx, 3
            //   83e904               | sub                 ecx, 4
            //   720c                 | jb                  0xe
            //   83e003               | and                 eax, 3

        $sequence_19 = { 895dd0 8945d8 8bf8 897dd4 8b5dd0 ebab c745e424714000 }
            // n = 7, score = 100
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8bf8                 | mov                 edi, eax
            //   897dd4               | mov                 dword ptr [ebp - 0x2c], edi
            //   8b5dd0               | mov                 ebx, dword ptr [ebp - 0x30]
            //   ebab                 | jmp                 0xffffffad
            //   c745e424714000       | mov                 dword ptr [ebp - 0x1c], 0x407124

        $sequence_20 = { 81e1ff000000 8a99b0e74600 8898b0e74600 40 8891b0e74600 3d00010000 }
            // n = 6, score = 100
            //   81e1ff000000         | and                 ecx, 0xff
            //   8a99b0e74600         | mov                 bl, byte ptr [ecx + 0x46e7b0]
            //   8898b0e74600         | mov                 byte ptr [eax + 0x46e7b0], bl
            //   40                   | inc                 eax
            //   8891b0e74600         | mov                 byte ptr [ecx + 0x46e7b0], dl
            //   3d00010000           | cmp                 eax, 0x100

        $sequence_21 = { 001458 40 0023 d18a0688078a 46 018847018a46 }
            // n = 6, score = 100
            //   001458               | add                 byte ptr [eax + ebx*2], dl
            //   40                   | inc                 eax
            //   0023                 | add                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi
            //   018847018a46         | add                 dword ptr [eax + 0x468a0147], ecx

    condition:
        7 of them and filesize < 1642496
}