rule win_bazarbackdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bazarbackdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bazarbackdoor"
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
        $sequence_0 = { 8a03 3c20 7709 84c0 }
            // n = 4, score = 1800
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   3c20                 | cmp                 al, 0x20
            //   7709                 | ja                  0xb
            //   84c0                 | test                al, al

        $sequence_1 = { 0fb6c8 e8???????? 85c0 7403 }
            // n = 4, score = 1800
            //   0fb6c8               | movzx               ecx, al
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_2 = { 7507 4084ff 400f94c7 0fb6c8 }
            // n = 4, score = 1600
            //   7507                 | jne                 9
            //   4084ff               | inc                 eax
            //   400f94c7             | test                bh, bh
            //   0fb6c8               | inc                 eax

        $sequence_3 = { 741f 3c22 7507 4084ff }
            // n = 4, score = 1600
            //   741f                 | test                bh, bh
            //   3c22                 | je                  0x26
            //   7507                 | jmp                 0xffffffd4
            //   4084ff               | cmp                 al, 0x20

        $sequence_4 = { 7709 84c0 7431 4084ff 741f }
            // n = 5, score = 1600
            //   7709                 | sete                bh
            //   84c0                 | movzx               ecx, al
            //   7431                 | ja                  0xb
            //   4084ff               | test                al, al
            //   741f                 | je                  0x35

        $sequence_5 = { 7403 48ffc3 48ffc3 ebd2 3c20 7709 48ffc3 }
            // n = 7, score = 1600
            //   7403                 | mov                 al, byte ptr [ebx]
            //   48ffc3               | cmp                 al, 0x20
            //   48ffc3               | ja                  0xb
            //   ebd2                 | test                al, al
            //   3c20                 | je                  0x37
            //   7709                 | je                  5
            //   48ffc3               | dec                 eax

        $sequence_6 = { 41b80f100000 488bce 4889442420 ff15???????? }
            // n = 4, score = 1500
            //   41b80f100000         | test                bh, bh
            //   488bce               | movzx               ecx, al
            //   4889442420           | test                eax, eax
            //   ff15????????         |                     

        $sequence_7 = { ff15???????? 85c0 780a 4898 }
            // n = 4, score = 1500
            //   ff15????????         |                     
            //   85c0                 | sete                bh
            //   780a                 | movzx               ecx, al
            //   4898                 | inc                 eax

        $sequence_8 = { e9???????? 48637e3c 488d55e0 488b4c2458 4803fe ff15???????? 85c0 }
            // n = 7, score = 1300
            //   e9????????           |                     
            //   48637e3c             | test                bh, bh
            //   488d55e0             | inc                 eax
            //   488b4c2458           | sete                bh
            //   4803fe               | movzx               ecx, al
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 4885c0 7407 488bcb ffd0 eb03 }
            // n = 5, score = 1300
            //   4885c0               | dec                 eax
            //   7407                 | inc                 ebx
            //   488bcb               | dec                 eax
            //   ffd0                 | inc                 ebx
            //   eb03                 | jmp                 0xffffffd7

        $sequence_10 = { ba01000000 33c9 41b862678da4 448d4a2a }
            // n = 4, score = 1300
            //   ba01000000           | test                bh, bh
            //   33c9                 | inc                 eax
            //   41b862678da4         | sete                bh
            //   448d4a2a             | movzx               ecx, al

        $sequence_11 = { 740a 488d4c2420 ffd0 488bd8 }
            // n = 4, score = 1300
            //   740a                 | je                  5
            //   488d4c2420           | dec                 eax
            //   ffd0                 | inc                 ebx
            //   488bd8               | inc                 eax

        $sequence_12 = { 488905???????? 4885c0 750a b82d000000 e9???????? }
            // n = 5, score = 1300
            //   488905????????       |                     
            //   4885c0               | cmp                 al, 0x22
            //   750a                 | movzx               ecx, al
            //   b82d000000           | test                eax, eax
            //   e9????????           |                     

        $sequence_13 = { 4155 4156 4157 488da828fbffff 4881ecb0050000 }
            // n = 5, score = 1300
            //   4155                 | test                al, al
            //   4156                 | je                  0x35
            //   4157                 | inc                 eax
            //   488da828fbffff       | test                bh, bh
            //   4881ecb0050000       | je                  0x28

        $sequence_14 = { ff15???????? 0fb74f02 0fb7d8 ff15???????? 0fb74f08 }
            // n = 5, score = 1100
            //   ff15????????         |                     
            //   0fb74f02             | mov                 eax, 0x100f
            //   0fb7d8               | dec                 eax
            //   ff15????????         |                     
            //   0fb74f08             | mov                 ecx, esi

        $sequence_15 = { 7507 33c0 e9???????? b8ff000000 }
            // n = 4, score = 1000
            //   7507                 | cmp                 al, 0x20
            //   33c0                 | ja                  0xb
            //   e9????????           |                     
            //   b8ff000000           | dec                 eax

        $sequence_16 = { c3 0fb74c0818 b80b010000 663bc8 }
            // n = 4, score = 900
            //   c3                   | dec                 eax
            //   0fb74c0818           | cwde                
            //   b80b010000           | inc                 ecx
            //   663bc8               | mov                 eax, 0x100f

        $sequence_17 = { ffd0 90 4883c430 5b }
            // n = 4, score = 800
            //   ffd0                 | dec                 eax
            //   90                   | mov                 dword ptr [esp + 0x20], eax
            //   4883c430             | test                eax, eax
            //   5b                   | js                  0xe

        $sequence_18 = { e8???????? 4889c7 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4889c7               | cwde                
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_19 = { ff15???????? 4889c1 31d2 4d89e0 }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   4889c1               | dec                 eax
            //   31d2                 | cwde                
            //   4d89e0               | test                eax, eax

        $sequence_20 = { 31ff 4889c1 31d2 4989f0 }
            // n = 4, score = 800
            //   31ff                 | js                  0xc
            //   4889c1               | dec                 eax
            //   31d2                 | cwde                
            //   4989f0               | call                eax

        $sequence_21 = { e8???????? 4c89e1 e8???????? 8b05???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4c89e1               | test                eax, eax
            //   e8????????           |                     
            //   8b05????????         |                     

        $sequence_22 = { 4889f1 e8???????? 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   4889f1               | dec                 eax
            //   e8????????           |                     
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_23 = { 7528 0fb64b04 0fb6d1 80f973 }
            // n = 4, score = 700
            //   7528                 | js                  0x13
            //   0fb64b04             | dec                 eax
            //   0fb6d1               | cwde                
            //   80f973               | inc                 ecx

        $sequence_24 = { c744242880000000 c744242003000000 4889f9 ba00000080 41b801000000 }
            // n = 5, score = 700
            //   c744242880000000     | arpl                word ptr [esi + 0x3c], di
            //   c744242003000000     | dec                 eax
            //   4889f9               | lea                 edx, [ebp - 0x20]
            //   ba00000080           | dec                 eax
            //   41b801000000         | mov                 ecx, dword ptr [esp + 0x58]

        $sequence_25 = { 30da 750b 08c1 80f101 7504 }
            // n = 5, score = 700
            //   30da                 | je                  0x26
            //   750b                 | ja                  0xb
            //   08c1                 | test                al, al
            //   80f101               | je                  0x33
            //   7504                 | inc                 eax

        $sequence_26 = { 38d3 7509 08c1 80f101 7502 }
            // n = 5, score = 700
            //   38d3                 | je                  0x33
            //   7509                 | inc                 eax
            //   08c1                 | test                bh, bh
            //   80f101               | je                  0x24
            //   7502                 | cmp                 al, 0x22

        $sequence_27 = { 31ed 4889c1 31d2 4989d8 }
            // n = 4, score = 700
            //   31ed                 | dec                 eax
            //   4889c1               | mov                 dword ptr [esp + 0x20], eax
            //   31d2                 | test                eax, eax
            //   4989d8               | dec                 eax

        $sequence_28 = { 4889c1 31d2 4989f8 ff15???????? 4885c0 }
            // n = 5, score = 700
            //   4889c1               | inc                 ecx
            //   31d2                 | mov                 eax, 0x100f
            //   4989f8               | dec                 eax
            //   ff15????????         |                     
            //   4885c0               | mov                 ecx, esi

        $sequence_29 = { ff15???????? 31db 4889c1 31d2 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   31db                 | inc                 ecx
            //   4889c1               | mov                 eax, 0x100f
            //   31d2                 | dec                 eax

        $sequence_30 = { 8b0d???????? 8d50ff 0fafd0 89d0 83f0fe 85d0 }
            // n = 6, score = 700
            //   8b0d????????         |                     
            //   8d50ff               | mov                 dword ptr [esp + 0x20], eax
            //   0fafd0               | test                eax, eax
            //   89d0                 | js                  0xe
            //   83f0fe               | dec                 eax
            //   85d0                 | cwde                

        $sequence_31 = { 83ff09 0f9fc3 83ff0a 0f9cc0 }
            // n = 4, score = 700
            //   83ff09               | js                  0xe
            //   0f9fc3               | dec                 eax
            //   83ff0a               | mov                 ecx, esi
            //   0f9cc0               | dec                 eax

        $sequence_32 = { e8???????? 4889f9 4889f2 ffd0 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   4889f9               | dec                 eax
            //   4889f2               | cwde                
            //   ffd0                 | dec                 eax

        $sequence_33 = { 0fb6d1 80f973 7504 0fb65305 33c0 80f973 0f94c0 }
            // n = 7, score = 700
            //   0fb6d1               | je                  0x80
            //   80f973               | dec                 eax
            //   7504                 | mov                 dword ptr [esp + 8], ebx
            //   0fb65305             | mov                 byte ptr [esp + 0x10], dl
            //   33c0                 | push                edi
            //   80f973               | inc                 ecx
            //   0f94c0               | mov                 eax, 0x100f

        $sequence_34 = { 8b05???????? 8b15???????? 8d58ff 0fafd8 }
            // n = 4, score = 700
            //   8b05????????         |                     
            //   8b15????????         |                     
            //   8d58ff               | mov                 dword ptr [esp + 0x20], eax
            //   0fafd8               | test                eax, eax

        $sequence_35 = { 8bd3 e8???????? 33c0 e9???????? }
            // n = 4, score = 700
            //   8bd3                 | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     
            //   33c0                 | test                eax, eax
            //   e9????????           |                     

        $sequence_36 = { 38ca 7506 08d8 3401 }
            // n = 4, score = 700
            //   38ca                 | dec                 eax
            //   7506                 | inc                 ebx
            //   08d8                 | jmp                 0xffffffda
            //   3401                 | cmp                 al, 0x20

        $sequence_37 = { 84d2 7405 80fa2e 750f 0fb6c1 }
            // n = 5, score = 600
            //   84d2                 | mov                 dword ptr [esp + 0x20], eax
            //   7405                 | test                eax, eax
            //   80fa2e               | dec                 eax
            //   750f                 | mov                 dword ptr [esp + 0x20], eax
            //   0fb6c1               | test                eax, eax

        $sequence_38 = { 89f0 4883c450 5b 5f }
            // n = 4, score = 600
            //   89f0                 | jne                 6
            //   4883c450             | movzx               edx, byte ptr [ebx + 5]
            //   5b                   | xor                 eax, eax
            //   5f                   | cmp                 cl, 0x73

        $sequence_39 = { e8???????? 4c897c2420 4889d9 89fa }
            // n = 4, score = 600
            //   e8????????           |                     
            //   4c897c2420           | sete                al
            //   4889d9               | jne                 0x2a
            //   89fa                 | movzx               ecx, byte ptr [ebx + 4]

        $sequence_40 = { 7404 3c2e 750b 8ac1 2ac2 fec8 88042a }
            // n = 7, score = 400
            //   7404                 | push                eax
            //   3c2e                 | movzx               eax, word ptr [ebp - 0x16]
            //   750b                 | push                eax
            //   8ac1                 | movzx               eax, word ptr [ebp - 0x18]
            //   2ac2                 | push                eax
            //   fec8                 | je                  6
            //   88042a               | cmp                 al, 0x2e

        $sequence_41 = { 03ef 8364241000 03df 837e1800 7626 }
            // n = 5, score = 400
            //   03ef                 | dec                 al
            //   8364241000           | mov                 byte ptr [edx + ebp], al
            //   03df                 | test                esi, esi
            //   837e1800             | jne                 0x6f
            //   7626                 | mov                 esi, eax

        $sequence_42 = { 50 ff15???????? 8b45f0 894604 85c0 740c }
            // n = 6, score = 400
            //   50                   | mov                 al, cl
            //   ff15????????         |                     
            //   8b45f0               | sub                 al, dl
            //   894604               | dec                 al
            //   85c0                 | mov                 byte ptr [edx + ebp], al
            //   740c                 | mov                 edx, ecx

        $sequence_43 = { 894604 85c0 740c 8b5508 8b0e e8???????? }
            // n = 6, score = 400
            //   894604               | add                 ebp, edi
            //   85c0                 | and                 dword ptr [esp + 0x10], 0
            //   740c                 | add                 ebx, edi
            //   8b5508               | cmp                 dword ptr [esi + 0x18], 0
            //   8b0e                 | jbe                 0x33
            //   e8????????           |                     

        $sequence_44 = { 7408 8818 40 83ee01 75f8 }
            // n = 5, score = 400
            //   7408                 | push                eax
            //   8818                 | mov                 eax, dword ptr [ebp - 0x10]
            //   40                   | mov                 dword ptr [esi + 4], eax
            //   83ee01               | test                eax, eax
            //   75f8                 | je                  0x13

        $sequence_45 = { 66890d???????? 0fb7ca ff15???????? b901000000 66c746020100 }
            // n = 5, score = 400
            //   66890d????????       |                     
            //   0fb7ca               | js                  0xe
            //   ff15????????         |                     
            //   b901000000           | dec                 eax
            //   66c746020100         | mov                 ecx, esi

        $sequence_46 = { 0fb745e8 50 68???????? e8???????? }
            // n = 4, score = 400
            //   0fb745e8             | inc                 ebx
            //   50                   | mov                 al, byte ptr [ebx]
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_47 = { 85f6 756d e8???????? 8bf0 8935???????? }
            // n = 5, score = 400
            //   85f6                 | jne                 0xd
            //   756d                 | mov                 al, cl
            //   e8????????           |                     
            //   8bf0                 | sub                 al, dl
            //   8935????????         |                     

        $sequence_48 = { 3bcf 72e5 53 8b1d???????? ffd3 8b3d???????? }
            // n = 6, score = 300
            //   3bcf                 | cmp                 ecx, edi
            //   72e5                 | jb                  0xffffffe7
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   ffd3                 | call                ebx
            //   8b3d????????         |                     

        $sequence_49 = { 6a00 ff7604 50 51 }
            // n = 4, score = 300
            //   6a00                 | cmovne              ebx, eax
            //   ff7604               | inc                 eax
            //   50                   | xor                 bh, bh
            //   51                   | mov                 al, byte ptr [ebx]

        $sequence_50 = { 85d2 740d 33d2 83f902 }
            // n = 4, score = 300
            //   85d2                 | test                edx, edx
            //   740d                 | je                  0xf
            //   33d2                 | xor                 edx, edx
            //   83f902               | cmp                 ecx, 2

        $sequence_51 = { 8bc2 c1f808 0fb6c0 50 0fb6c2 50 }
            // n = 6, score = 300
            //   8bc2                 | mov                 eax, edx
            //   c1f808               | sar                 eax, 8
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax
            //   0fb6c2               | movzx               eax, dl
            //   50                   | push                eax

        $sequence_52 = { 660f73d801 660febd0 660f7ed0 84c0 }
            // n = 4, score = 300
            //   660f73d801           | psrldq              xmm0, 1
            //   660febd0             | por                 xmm2, xmm0
            //   660f7ed0             | movd                eax, xmm2
            //   84c0                 | test                al, al

        $sequence_53 = { 8bf0 85f6 745c 57 8d450c 50 }
            // n = 6, score = 300
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   745c                 | je                  0x5e
            //   57                   | push                edi
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   50                   | push                eax

        $sequence_54 = { b800308804 6a00 50 6a00 6a00 6a00 }
            // n = 6, score = 300
            //   b800308804           | cmp                 al, 0x20
            //   6a00                 | ja                  0x12
            //   50                   | test                al, al
            //   6a00                 | je                  0x3e
            //   6a00                 | test                eax, eax
            //   6a00                 | je                  7

        $sequence_55 = { 0fb6c1 50 8bc2 c1f808 }
            // n = 4, score = 300
            //   0fb6c1               | jne                 9
            //   50                   | inc                 eax
            //   8bc2                 | test                bh, bh
            //   c1f808               | inc                 eax

        $sequence_56 = { 6a01 6a04 68???????? ff15???????? 8bf8 83ffff }
            // n = 6, score = 300
            //   6a01                 | push                1
            //   6a04                 | push                4
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1

        $sequence_57 = { 0f95c2 83c224 eb05 ba29000000 }
            // n = 4, score = 300
            //   0f95c2               | setne               dl
            //   83c224               | add                 edx, 0x24
            //   eb05                 | jmp                 7
            //   ba29000000           | mov                 edx, 0x29

        $sequence_58 = { 33d2 83f902 0f95c2 83c224 }
            // n = 4, score = 300
            //   33d2                 | xor                 edx, edx
            //   83f902               | cmp                 ecx, 2
            //   0f95c2               | setne               dl
            //   83c224               | add                 edx, 0x24

        $sequence_59 = { 488b942400010000 488b8c24f0000000 e8???????? 85c0 7507 }
            // n = 5, score = 100
            //   488b942400010000     | js                  0x16
            //   488b8c24f0000000     | inc                 ecx
            //   e8????????           |                     
            //   85c0                 | mov                 eax, 0x100f
            //   7507                 | dec                 eax

        $sequence_60 = { 4825ffff0000 0fb7c0 488b4c2430 2b4110 89442420 e9???????? 488b442430 }
            // n = 7, score = 100
            //   4825ffff0000         | mov                 ecx, esi
            //   0fb7c0               | dec                 eax
            //   488b4c2430           | mov                 dword ptr [esp + 0x20], eax
            //   2b4110               | test                eax, eax
            //   89442420             | js                  0x16
            //   e9????????           |                     
            //   488b442430           | dec                 eax

        $sequence_61 = { 837c242000 7529 488b842488000000 488b5040 488b4c2448 }
            // n = 5, score = 100
            //   837c242000           | inc                 ecx
            //   7529                 | push                edi
            //   488b842488000000     | dec                 eax
            //   488b5040             | lea                 ebp, [eax - 0x4d8]
            //   488b4c2448           | dec                 eax

        $sequence_62 = { 4889542410 48894c2408 4883ec78 488b842488000000 488b00 488b8c2488000000 }
            // n = 6, score = 100
            //   4889542410           | sub                 esp, 0x5b0
            //   48894c2408           | dec                 eax
            //   4883ec78             | test                eax, eax
            //   488b842488000000     | jne                 0xf
            //   488b00               | mov                 eax, 0x2d
            //   488b8c2488000000     | je                  0xc

        $sequence_63 = { 33c0 e9???????? 488b442438 8b4038 83e001 85c0 }
            // n = 6, score = 100
            //   33c0                 | test                eax, eax
            //   e9????????           |                     
            //   488b442438           | inc                 ecx
            //   8b4038               | push                ebp
            //   83e001               | inc                 ecx
            //   85c0                 | push                esi

        $sequence_64 = { 488b842488000000 8b4018 ffc0 488b8c2488000000 894118 488b442428 }
            // n = 6, score = 100
            //   488b842488000000     | cwde                
            //   8b4018               | dec                 eax
            //   ffc0                 | mov                 ecx, esi
            //   488b8c2488000000     | dec                 eax
            //   894118               | mov                 dword ptr [esp + 0x20], eax
            //   488b442428           | test                eax, eax

        $sequence_65 = { 488b442428 8b4008 480b442440 4889442448 }
            // n = 4, score = 100
            //   488b442428           | dec                 eax
            //   8b4008               | lea                 ecx, [esp + 0x20]
            //   480b442440           | call                eax
            //   4889442448           | dec                 eax

        $sequence_66 = { 0fb7c0 85c0 754f 488b842480000000 4825ffff0000 0fb7c0 488b4c2430 }
            // n = 7, score = 100
            //   0fb7c0               | js                  0xe
            //   85c0                 | inc                 ecx
            //   754f                 | mov                 eax, 0x100f
            //   488b842480000000     | dec                 eax
            //   4825ffff0000         | mov                 ecx, esi
            //   0fb7c0               | dec                 eax
            //   488b4c2430           | mov                 dword ptr [esp + 0x20], eax

    condition:
        7 of them and filesize < 2088960
}