rule win_smokeloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.smokeloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smokeloader"
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
        $sequence_0 = { ff15???????? 8d45f0 50 8d45e8 50 8d45e0 50 }
            // n = 7, score = 1300
            //   ff15????????         |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax

        $sequence_1 = { 50 8d45e0 50 56 ff15???????? 56 }
            // n = 6, score = 1100
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_2 = { 6a00 53 ff15???????? 8d45f0 }
            // n = 4, score = 1100
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_3 = { 57 ff15???????? 6a00 6800000002 }
            // n = 4, score = 1100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6800000002           | push                0x2000000

        $sequence_4 = { ff15???????? 8bf0 8d45dc 50 6a00 }
            // n = 5, score = 1100
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_5 = { 56 8d45fc 50 57 57 6a19 }
            // n = 6, score = 900
            //   56                   | push                0
            //   8d45fc               | mov                 ax, gs
            //   50                   | test                ax, ax
            //   57                   | je                  0xb
            //   57                   | mov                 ax, gs
            //   6a19                 | test                ax, ax

        $sequence_6 = { 50 56 681f000f00 57 }
            // n = 4, score = 900
            //   50                   | push                eax
            //   56                   | push                esi
            //   681f000f00           | push                eax
            //   57                   | push                esi

        $sequence_7 = { 0fb64405dc 50 8d45ec 50 }
            // n = 4, score = 900
            //   0fb64405dc           | mov                 ax, gs
            //   50                   | test                ax, ax
            //   8d45ec               | je                  0xb
            //   50                   | mov                 ax, gs

        $sequence_8 = { ff15???????? bf90010000 8bcf e8???????? }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   bf90010000           | mov                 edi, 0x190
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_9 = { 668ce8 6685c0 7406 fe05???????? }
            // n = 4, score = 900
            //   668ce8               | push                eax
            //   6685c0               | push                esi
            //   7406                 | mov                 esi, eax
            //   fe05????????         |                     

        $sequence_10 = { e8???????? 8bf0 8d45fc 50 ff75fc 56 6a19 }
            // n = 7, score = 900
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   56                   | push                esi
            //   6a19                 | push                0x19

        $sequence_11 = { 740a 83c104 83f920 72f0 }
            // n = 4, score = 900
            //   740a                 | je                  0xc
            //   83c104               | add                 ecx, 4
            //   83f920               | cmp                 ecx, 0x20
            //   72f0                 | jb                  0xfffffff2

        $sequence_12 = { 8b07 03c3 50 ff15???????? }
            // n = 4, score = 800
            //   8b07                 | push                0
            //   03c3                 | push                ebx
            //   50                   | push                edi
            //   ff15????????         |                     

        $sequence_13 = { ff15???????? 50 56 6a00 ff15???????? }
            // n = 5, score = 800
            //   ff15????????         |                     
            //   50                   | lea                 eax, [ebp - 0x24]
            //   56                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_14 = { 7507 33c0 e9???????? e8???????? b904010000 }
            // n = 5, score = 800
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   e8????????           |                     
            //   b904010000           | mov                 ecx, 0x104

        $sequence_15 = { 72f0 eb19 8365fc00 8d45fc 50 }
            // n = 5, score = 800
            //   72f0                 | lea                 eax, [ebp - 4]
            //   eb19                 | push                eax
            //   8365fc00             | push                edi
            //   8d45fc               | push                edi
            //   50                   | push                0x19

        $sequence_16 = { c745ec25303258 885df0 8945fc 0fb64405dc }
            // n = 4, score = 700
            //   c745ec25303258       | lea                 eax, [ebp - 4]
            //   885df0               | push                eax
            //   8945fc               | push                dword ptr [ebp - 4]
            //   0fb64405dc           | push                esi

        $sequence_17 = { 8d45f4 53 56 57 68000000f0 6a01 }
            // n = 6, score = 700
            //   8d45f4               | push                esi
            //   53                   | push                eax
            //   56                   | push                esi
            //   57                   | push                0xf001f
            //   68000000f0           | push                edi
            //   6a01                 | mov                 esi, eax

        $sequence_18 = { 7404 8b37 eb03 8b773c 03f7 33c0 33db }
            // n = 7, score = 700
            //   7404                 | push                0x19
            //   8b37                 | movzx               eax, byte ptr [ebp + eax - 0x24]
            //   eb03                 | push                eax
            //   8b773c               | lea                 eax, [ebp - 0x14]
            //   03f7                 | push                eax
            //   33c0                 | push                esi
            //   33db                 | lea                 eax, [ebp - 4]

        $sequence_19 = { 8b7d10 50 57 56 53 e8???????? }
            // n = 6, score = 500
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   57                   | push                edi
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_20 = { 89c6 6804010000 56 57 }
            // n = 4, score = 500
            //   89c6                 | mov                 esi, eax
            //   6804010000           | push                0x104
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_21 = { 66894603 8d8de8fdffff 50 50 50 50 51 }
            // n = 7, score = 500
            //   66894603             | mov                 word ptr [esi + 3], ax
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_22 = { 6800800000 52 51 6aff }
            // n = 4, score = 500
            //   6800800000           | push                0x8000
            //   52                   | push                edx
            //   51                   | push                ecx
            //   6aff                 | push                -1

        $sequence_23 = { c60653 56 6a00 6a00 6a00 }
            // n = 5, score = 500
            //   c60653               | mov                 byte ptr [esi], 0x53
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_24 = { e8???????? 8d8decfdffff 8d95f0fdffff c70200000000 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   c70200000000         | mov                 dword ptr [edx], 0

        $sequence_25 = { 01d4 8d85f0fdffff 8b750c 8b7d10 50 57 }
            // n = 6, score = 500
            //   01d4                 | add                 esp, edx
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_26 = { ffb5f0fdffff 50 53 e8???????? 8d8decfdffff }
            // n = 5, score = 500
            //   ffb5f0fdffff         | push                dword ptr [ebp - 0x210]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]

        $sequence_27 = { 60 89c6 89cf fc }
            // n = 4, score = 400
            //   60                   | pop                 ebp
            //   89c6                 | aaa                 
            //   89cf                 | mov                 edi, 0x190
            //   fc                   | mov                 ecx, edi

        $sequence_28 = { 55 89e5 81ec5c060000 53 }
            // n = 4, score = 400
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   81ec5c060000         | sub                 esp, 0x65c
            //   53                   | push                ebx

        $sequence_29 = { 89cf fc b280 31db a4 }
            // n = 5, score = 400
            //   89cf                 | cld                 
            //   fc                   | mov                 dl, 0x80
            //   b280                 | xor                 ebx, ebx
            //   31db                 | movsb               byte ptr es:[edi], byte ptr [esi]
            //   a4                   | mov                 esi, eax

        $sequence_30 = { 30d0 aa e2f3 7505 }
            // n = 4, score = 400
            //   30d0                 | xor                 al, dl
            //   aa                   | stosb               byte ptr es:[edi], al
            //   e2f3                 | loop                0xfffffff5
            //   7505                 | jne                 7

        $sequence_31 = { 4889542440 488d55b0 0f1145b0 0f1145d0 0f1145f0 4889542438 488d55d0 }
            // n = 7, score = 300
            //   4889542440           | lea                 eax, [ebp + 0x40]
            //   488d55b0             | dec                 eax
            //   0f1145b0             | mov                 ecx, 0x80000002
            //   0f1145d0             | dec                 ecx
            //   0f1145f0             | mov                 edx, esi
            //   4889542438           | dec                 eax
            //   488d55d0             | mov                 dword ptr [esp + 0x20], eax

        $sequence_32 = { 49 8d3c8c 8b37 4c 01c6 }
            // n = 5, score = 300
            //   49                   | dec                 ecx
            //   8d3c8c               | lea                 edi, [esp + ecx*4]
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   4c                   | dec                 esp
            //   01c6                 | add                 esi, eax

        $sequence_33 = { 4d 01c4 ffc9 49 8d3c8c }
            // n = 5, score = 300
            //   4d                   | dec                 ebp
            //   01c4                 | add                 esp, eax
            //   ffc9                 | dec                 ecx
            //   49                   | dec                 ecx
            //   8d3c8c               | lea                 edi, [esp + ecx*4]

        $sequence_34 = { 668b0c4f 41 8b7b1c 4c 01c7 8b048f 4c }
            // n = 7, score = 300
            //   668b0c4f             | mov                 cx, word ptr [edi + ecx*2]
            //   41                   | inc                 ecx
            //   8b7b1c               | mov                 edi, dword ptr [ebx + 0x1c]
            //   4c                   | dec                 esp
            //   01c7                 | add                 edi, eax
            //   8b048f               | mov                 eax, dword ptr [edi + ecx*4]
            //   4c                   | dec                 esp

        $sequence_35 = { e8???????? 4103dc 3bde 7ca7 803d????????00 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   4103dc               | inc                 ebp
            //   3bde                 | xor                 edx, edx
            //   7ca7                 | inc                 ecx
            //   803d????????00       |                     

        $sequence_36 = { 488bec 4883ec50 33db 8d4b02 e8???????? }
            // n = 5, score = 300
            //   488bec               | dec                 eax
            //   4883ec50             | mov                 dword ptr [esp + 0x38], edx
            //   33db                 | dec                 eax
            //   8d4b02               | lea                 edx, [ebp - 0x30]
            //   e8????????           |                     

        $sequence_37 = { 4533d2 418af1 418bd8 488bea 488bf9 4c8d1c24 418bc2 }
            // n = 7, score = 300
            //   4533d2               | dec                 eax
            //   418af1               | mov                 dword ptr [esp + 0x40], edx
            //   418bd8               | dec                 eax
            //   488bea               | lea                 edx, [ebp - 0x50]
            //   488bf9               | movups              xmmword ptr [ebp - 0x50], xmm0
            //   4c8d1c24             | movups              xmmword ptr [ebp - 0x30], xmm0
            //   418bc2               | movups              xmmword ptr [ebp - 0x10], xmm0

        $sequence_38 = { 41b919000200 4533c0 4c8bf0 488d4540 48c7c102000080 498bd6 4889442420 }
            // n = 7, score = 300
            //   41b919000200         | inc                 ecx
            //   4533c0               | mov                 ecx, 0x20019
            //   4c8bf0               | inc                 ebp
            //   488d4540             | xor                 eax, eax
            //   48c7c102000080       | dec                 esp
            //   498bd6               | mov                 esi, eax
            //   4889442420           | dec                 eax

        $sequence_39 = { 31c0 ac 01c2 85c0 75f0 }
            // n = 5, score = 300
            //   31c0                 | xor                 eax, eax
            //   ac                   | lodsb               al, byte ptr [esi]
            //   01c2                 | add                 edx, eax
            //   85c0                 | test                eax, eax
            //   75f0                 | jne                 0xfffffff2

        $sequence_40 = { 41 8b4b18 45 8b6320 4d }
            // n = 5, score = 300
            //   41                   | inc                 ecx
            //   8b4b18               | mov                 ecx, dword ptr [ebx + 0x18]
            //   45                   | inc                 ebp
            //   8b6320               | mov                 esp, dword ptr [ebx + 0x20]
            //   4d                   | dec                 ebp

        $sequence_41 = { 8b7b24 4c 01c7 668b0c4f 41 8b7b1c }
            // n = 6, score = 300
            //   8b7b24               | mov                 edi, dword ptr [ebx + 0x24]
            //   4c                   | dec                 esp
            //   01c7                 | add                 edi, eax
            //   668b0c4f             | mov                 cx, word ptr [edi + ecx*2]
            //   41                   | inc                 ecx
            //   8b7b1c               | mov                 edi, dword ptr [ebx + 0x1c]

        $sequence_42 = { 89e5 81ec54040000 53 56 }
            // n = 4, score = 300
            //   89e5                 | lea                 eax, [ebp - 0x210]
            //   81ec54040000         | mov                 esi, dword ptr [ebp + 0xc]
            //   53                   | mov                 edi, dword ptr [ebp + 0x10]
            //   56                   | push                eax

        $sequence_43 = { 55 8bec 81ec88000000 57 c745e800000000 c745f400000000 }
            // n = 6, score = 200
            //   55                   | push                eax
            //   8bec                 | mov                 esi, dword ptr [ebp + 0xc]
            //   81ec88000000         | mov                 edi, dword ptr [ebp + 0x10]
            //   57                   | push                eax
            //   c745e800000000       | push                edi
            //   c745f400000000       | push                esi

        $sequence_44 = { 8b4218 3b4514 7526 8b8d78ffffff }
            // n = 4, score = 200
            //   8b4218               | mov                 edi, dword ptr [ebp + 0x10]
            //   3b4514               | push                eax
            //   7526                 | add                 esp, edx
            //   8b8d78ffffff         | lea                 eax, [ebp - 0x210]

        $sequence_45 = { c1e002 03471c 8b0428 01e8 }
            // n = 4, score = 200
            //   c1e002               | ret                 
            //   03471c               | push                esi
            //   8b0428               | add                 eax, ebp
            //   01e8                 | pop                 esi

        $sequence_46 = { 8b55ac 52 e8???????? 8d45d8 50 8b4dfc 51 }
            // n = 7, score = 200
            //   8b55ac               | mov                 esi, dword ptr [ebp + 0xc]
            //   52                   | mov                 edi, dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   8d45d8               | lea                 ecx, [ebp - 0x214]
            //   50                   | lea                 edx, [ebp - 0x210]
            //   8b4dfc               | mov                 dword ptr [edx], 0
            //   51                   | push                0x8000

        $sequence_47 = { 8b55f0 0355fc 034df8 8d84912b010000 }
            // n = 4, score = 200
            //   8b55f0               | push                edx
            //   0355fc               | push                ecx
            //   034df8               | xor                 eax, eax
            //   8d84912b010000       | mov                 word ptr [esi + 3], ax

        $sequence_48 = { 6bc928 8b55ec 8b440a08 8945e4 8b4d8c 6bc928 }
            // n = 6, score = 200
            //   6bc928               | lea                 eax, [ebp - 0x28]
            //   8b55ec               | push                eax
            //   8b440a08             | mov                 ecx, dword ptr [ebp - 4]
            //   8945e4               | push                ecx
            //   8b4d8c               | mov                 edx, dword ptr [ebp - 0x10]
            //   6bc928               | add                 edx, dword ptr [ebp - 4]

        $sequence_49 = { 8bec 83c4d0 1e 53 56 57 }
            // n = 6, score = 200
            //   8bec                 | movsb               byte ptr es:[edi], byte ptr [esi]
            //   83c4d0               | mov                 edi, ecx
            //   1e                   | cld                 
            //   53                   | mov                 dl, 0x80
            //   56                   | xor                 ebx, ebx
            //   57                   | movsb               byte ptr es:[edi], byte ptr [esi]

        $sequence_50 = { 8955cc 6a1c 6a00 8d45d8 }
            // n = 4, score = 200
            //   8955cc               | jne                 0x28
            //   6a1c                 | mov                 ecx, dword ptr [ebp - 0x88]
            //   6a00                 | mov                 edx, dword ptr [ebp - 0x54]
            //   8d45d8               | push                edx

        $sequence_51 = { 8b55d8 52 e8???????? c7459000000000 }
            // n = 4, score = 200
            //   8b55d8               | lea                 ecx, [ebp - 0x218]
            //   52                   | push                eax
            //   e8????????           |                     
            //   c7459000000000       | push                eax

        $sequence_52 = { 31d1 75ec 58 29c6 }
            // n = 4, score = 200
            //   31d1                 | mov                 edi, ecx
            //   75ec                 | cld                 
            //   58                   | mov                 dl, 0x80
            //   29c6                 | xor                 ebx, ebx

        $sequence_53 = { 8b453c 8b7c2878 01ef 8b7720 }
            // n = 4, score = 200
            //   8b453c               | jne                 0xfffffff0
            //   8b7c2878             | pop                 eax
            //   01ef                 | sub                 esi, eax
            //   8b7720               | mov                 ebp, esp

        $sequence_54 = { c9 c21000 55 89e5 81ec54040000 }
            // n = 5, score = 200
            //   c9                   | lea                 ecx, [ebp - 0x214]
            //   c21000               | lea                 edx, [ebp - 0x210]
            //   55                   | mov                 dword ptr [edx], 0
            //   89e5                 | push                0x8000
            //   81ec54040000         | push                edx

        $sequence_55 = { 8b7720 01ee 56 ad }
            // n = 4, score = 200
            //   8b7720               | cmp                 byte ptr [eax], 0
            //   01ee                 | jne                 0xfffffff7
            //   56                   | xor                 ecx, edx
            //   ad                   | jne                 0xfffffff2

        $sequence_56 = { 75f3 c3 56 89c2 8b453c }
            // n = 5, score = 200
            //   75f3                 | cld                 
            //   c3                   | mov                 dl, 0x80
            //   56                   | xor                 ebx, ebx
            //   89c2                 | movsb               byte ptr es:[edi], byte ptr [esi]
            //   8b453c               | mov                 bl, 2

        $sequence_57 = { 0faf55fc 8955fc 0fb645eb 3345e4 8845e3 8b4dfc 034d10 }
            // n = 7, score = 200
            //   0faf55fc             | push                ebx
            //   8955fc               | mov                 eax, dword ptr [ebp + 0x14]
            //   0fb645eb             | mov                 dword ptr [esi + 0x208], eax
            //   3345e4               | push                esi
            //   8845e3               | push                -1
            //   8b4dfc               | mov                 eax, dword ptr [edx + 0x18]
            //   034d10               | cmp                 eax, dword ptr [ebp + 0x14]

        $sequence_58 = { aa e2f3 7506 7404 }
            // n = 4, score = 200
            //   aa                   | push                ebx
            //   e2f3                 | push                esi
            //   7506                 | leave               
            //   7404                 | ret                 0x10

        $sequence_59 = { 99 54 8550e5 3c44 5d 5d }
            // n = 6, score = 100
            //   99                   | pop                 ebx
            //   54                   | leave               
            //   8550e5               | ret                 8
            //   3c44                 | push                ebp
            //   5d                   | mov                 ebp, esp
            //   5d                   | sub                 esp, 4

        $sequence_60 = { 1d61d61d25 5e 18550d d6 1545d60d7d }
            // n = 5, score = 100
            //   1d61d61d25           | je                  8
            //   5e                   | xor                 al, dl
            //   18550d               | stosb               byte ptr es:[edi], al
            //   d6                   | loop                0xfffffff5
            //   1545d60d7d           | jne                 0xa

        $sequence_61 = { 015d10 5d 1c5d 1e 5d 155d145d13 5d }
            // n = 7, score = 100
            //   015d10               | mov                 ebp, esp
            //   5d                   | sub                 esp, 0x454
            //   1c5d                 | push                ebx
            //   1e                   | push                esi
            //   5d                   | stosb               byte ptr es:[edi], al
            //   155d145d13           | loop                0xfffffff6
            //   5d                   | jne                 8

        $sequence_62 = { 145d 5d 5d 5d 03dd 635d52 }
            // n = 6, score = 100
            //   145d                 | xor                 al, dl
            //   5d                   | stosb               byte ptr es:[edi], al
            //   5d                   | loop                0xfffffff6
            //   5d                   | jne                 0xb
            //   03dd                 | je                  0xb
            //   635d52               | xor                 byte ptr [eax], dh

        $sequence_63 = { 3030 3228 2e5d 2b30 6e }
            // n = 5, score = 100
            //   3030                 | push                ebp
            //   3228                 | mov                 ebp, esp
            //   2e5d                 | sub                 esp, 0x454
            //   2b30                 | ret                 0x10
            //   6e                   | push                ebp

    condition:
        7 of them and filesize < 245760
}