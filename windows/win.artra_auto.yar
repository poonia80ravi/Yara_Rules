rule win_artra_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.artra."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.artra"
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
        $sequence_0 = { 8b442410 5f 5e 83c41c c21000 5f }
            // n = 6, score = 800
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   83c41c               | add                 esp, 0x1c
            //   c21000               | ret                 0x10
            //   5f                   | pop                 edi

        $sequence_1 = { 84d2 75f9 2bc7 3bc8 72e3 8bc6 8d5001 }
            // n = 7, score = 700
            //   84d2                 | test                dl, dl
            //   75f9                 | jne                 0xfffffffb
            //   2bc7                 | sub                 eax, edi
            //   3bc8                 | cmp                 ecx, eax
            //   72e3                 | jb                  0xffffffe5
            //   8bc6                 | mov                 eax, esi
            //   8d5001               | lea                 edx, [eax + 1]

        $sequence_2 = { 72e3 8bc6 8d5001 5f 8a08 40 84c9 }
            // n = 7, score = 700
            //   72e3                 | jb                  0xffffffe5
            //   8bc6                 | mov                 eax, esi
            //   8d5001               | lea                 edx, [eax + 1]
            //   5f                   | pop                 edi
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl

        $sequence_3 = { 800431f3 8bc6 41 8d7801 }
            // n = 4, score = 700
            //   800431f3             | add                 byte ptr [ecx + esi], 0xf3
            //   8bc6                 | mov                 eax, esi
            //   41                   | inc                 ecx
            //   8d7801               | lea                 edi, [eax + 1]

        $sequence_4 = { 8bc6 57 33c9 8d7801 8da42400000000 8a10 40 }
            // n = 7, score = 700
            //   8bc6                 | mov                 eax, esi
            //   57                   | push                edi
            //   33c9                 | xor                 ecx, ecx
            //   8d7801               | lea                 edi, [eax + 1]
            //   8da42400000000       | lea                 esp, [esp]
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   40                   | inc                 eax

        $sequence_5 = { 8b2d???????? 90 8b542410 8d4c2410 }
            // n = 4, score = 600
            //   8b2d????????         |                     
            //   90                   | nop                 
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

        $sequence_6 = { ffd7 85c0 7445 53 8b1d???????? 55 8b2d???????? }
            // n = 7, score = 600
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7445                 | je                  0x47
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   55                   | push                ebp
            //   8b2d????????         |                     

        $sequence_7 = { 8d54241c 52 ffd7 85c0 75cc 5d }
            // n = 6, score = 600
            //   8d54241c             | lea                 edx, [esp + 0x1c]
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   75cc                 | jne                 0xffffffce
            //   5d                   | pop                 ebp

        $sequence_8 = { 6a00 6a00 8d442414 50 ffd7 85c0 }
            // n = 6, score = 600
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax

        $sequence_9 = { e8???????? 8b3d???????? 6a00 6a00 6a00 8d442414 }
            // n = 6, score = 600
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_10 = { 2bc2 03fb 8a4f01 47 }
            // n = 4, score = 600
            //   2bc2                 | sub                 eax, edx
            //   03fb                 | add                 edi, ebx
            //   8a4f01               | mov                 cl, byte ptr [edi + 1]
            //   47                   | inc                 edi

        $sequence_11 = { 57 ff15???????? 6a6d 56 ff15???????? 8bf0 e8???????? }
            // n = 7, score = 600
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6a6d                 | push                0x6d
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     

        $sequence_12 = { 8bf8 85ff 0f8488000000 6a00 57 ff15???????? 57 }
            // n = 7, score = 600
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f8488000000         | je                  0x8e
            //   6a00                 | push                0
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi

        $sequence_13 = { 880a 40 42 84c9 75f6 e8???????? }
            // n = 6, score = 600
            //   880a                 | mov                 byte ptr [edx], cl
            //   40                   | inc                 eax
            //   42                   | inc                 edx
            //   84c9                 | test                cl, cl
            //   75f6                 | jne                 0xfffffff8
            //   e8????????           |                     

        $sequence_14 = { 75f8 8a15???????? 8817 8d842484020000 8bc8 }
            // n = 5, score = 500
            //   75f8                 | jne                 0xfffffffa
            //   8a15????????         |                     
            //   8817                 | mov                 byte ptr [edi], dl
            //   8d842484020000       | lea                 eax, [esp + 0x284]
            //   8bc8                 | mov                 ecx, eax

        $sequence_15 = { c644240d6d c644240e65 c644240f00 c644241053 c64424114f }
            // n = 5, score = 500
            //   c644240d6d           | mov                 byte ptr [esp + 0xd], 0x6d
            //   c644240e65           | mov                 byte ptr [esp + 0xe], 0x65
            //   c644240f00           | mov                 byte ptr [esp + 0xf], 0
            //   c644241053           | mov                 byte ptr [esp + 0x10], 0x53
            //   c64424114f           | mov                 byte ptr [esp + 0x11], 0x4f

        $sequence_16 = { 50 64892500000000 81ec60060000 53 55 33db 56 }
            // n = 7, score = 500
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   81ec60060000         | sub                 esp, 0x660
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi

        $sequence_17 = { 0f844d030000 8b01 8b5004 6aff ffd2 83f8ff 0f841c030000 }
            // n = 7, score = 500
            //   0f844d030000         | je                  0x353
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   6aff                 | push                -1
            //   ffd2                 | call                edx
            //   83f8ff               | cmp                 eax, -1
            //   0f841c030000         | je                  0x322

        $sequence_18 = { ffd6 85c0 75cc 5d 5b 8b442410 }
            // n = 6, score = 400
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   75cc                 | jne                 0xffffffce
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]

        $sequence_19 = { 8bc6 c1f805 8b0485e03b4100 83e61f }
            // n = 4, score = 400
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b0485e03b4100       | mov                 eax, dword ptr [eax*4 + 0x413be0]
            //   83e61f               | and                 esi, 0x1f

        $sequence_20 = { 7733 885c2c18 45 83fd02 7529 8d742418 }
            // n = 6, score = 400
            //   7733                 | ja                  0x35
            //   885c2c18             | mov                 byte ptr [esp + ebp + 0x18], bl
            //   45                   | inc                 ebp
            //   83fd02               | cmp                 ebp, 2
            //   7529                 | jne                 0x2b
            //   8d742418             | lea                 esi, [esp + 0x18]

        $sequence_21 = { 8bec 8b4508 ff34c520104100 ff15???????? 5d }
            // n = 5, score = 400
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c520104100       | push                dword ptr [eax*8 + 0x411020]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp

        $sequence_22 = { 51 68???????? 6a00 68ffff0000 68???????? }
            // n = 5, score = 400
            //   51                   | push                ecx
            //   68????????           |                     
            //   6a00                 | push                0
            //   68ffff0000           | push                0xffff
            //   68????????           |                     

        $sequence_23 = { 8b35???????? 6a00 6a00 6a00 8d4c2414 51 ffd6 }
            // n = 7, score = 200
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   51                   | push                ecx
            //   ffd6                 | call                esi

        $sequence_24 = { 33c0 5e 83c41c c21000 8b35???????? 6a00 6a00 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   83c41c               | add                 esp, 0x1c
            //   c21000               | ret                 0x10
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_25 = { 8a08 40 84c9 75f9 2bc2 880c30 59 }
            // n = 7, score = 200
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   880c30               | mov                 byte ptr [eax + esi], cl
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 811008
}