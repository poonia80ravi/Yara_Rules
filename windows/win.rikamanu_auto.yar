rule win_rikamanu_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.rikamanu."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rikamanu"
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
        $sequence_0 = { e8???????? 6a14 ff15???????? a801 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   6a14                 | push                0x14
            //   ff15????????         |                     
            //   a801                 | test                al, 1

        $sequence_1 = { 50 ff15???????? 8b35???????? 3d80969800 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   3d80969800           | cmp                 eax, 0x989680

        $sequence_2 = { e8???????? 6808020000 8d85ecfbffff 53 50 e8???????? 8d85ecfbffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6808020000           | push                0x208
            //   8d85ecfbffff         | lea                 eax, [ebp - 0x414]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85ecfbffff         | lea                 eax, [ebp - 0x414]

        $sequence_3 = { 85c0 751d 8b45e8 50 ff15???????? 33c0 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   751d                 | jne                 0x1f
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 56 ff15???????? 8b542414 52 6a00 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   6a00                 | push                0

        $sequence_5 = { 83c604 84c0 7593 8b8c2470020000 8b942474020000 51 }
            // n = 6, score = 100
            //   83c604               | add                 esi, 4
            //   84c0                 | test                al, al
            //   7593                 | jne                 0xffffff95
            //   8b8c2470020000       | mov                 ecx, dword ptr [esp + 0x270]
            //   8b942474020000       | mov                 edx, dword ptr [esp + 0x274]
            //   51                   | push                ecx

        $sequence_6 = { 0fb63e 0fb6c0 eb12 8b45e0 8a800c982400 }
            // n = 5, score = 100
            //   0fb63e               | movzx               edi, byte ptr [esi]
            //   0fb6c0               | movzx               eax, al
            //   eb12                 | jmp                 0x14
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8a800c982400         | mov                 al, byte ptr [eax + 0x24980c]

        $sequence_7 = { 66837e1612 751e 0fb74e12 6685c9 }
            // n = 4, score = 100
            //   66837e1612           | cmp                 word ptr [esi + 0x16], 0x12
            //   751e                 | jne                 0x20
            //   0fb74e12             | movzx               ecx, word ptr [esi + 0x12]
            //   6685c9               | test                cx, cx

        $sequence_8 = { 8d942440060000 51 52 e8???????? 83c408 }
            // n = 5, score = 100
            //   8d942440060000       | lea                 edx, [esp + 0x640]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_9 = { ff15???????? 8b35???????? b906000000 33c0 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   b906000000           | mov                 ecx, 6
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { e8???????? 68???????? 68???????? e8???????? 85c0 7517 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19

        $sequence_11 = { 680000cf00 57 57 53 ff15???????? }
            // n = 5, score = 100
            //   680000cf00           | push                0xcf0000
            //   57                   | push                edi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_12 = { 7410 8088????????20 8a9405ecfcffff ebe3 80a0a0a6400000 40 41 }
            // n = 7, score = 100
            //   7410                 | je                  0x12
            //   8088????????20       |                     
            //   8a9405ecfcffff       | mov                 dl, byte ptr [ebp + eax - 0x314]
            //   ebe3                 | jmp                 0xffffffe5
            //   80a0a0a6400000       | and                 byte ptr [eax + 0x40a6a0], 0
            //   40                   | inc                 eax
            //   41                   | inc                 ecx

        $sequence_13 = { ff15???????? 8b04bd383f4100 830c06ff 33c0 eb16 e8???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8b04bd383f4100       | mov                 eax, dword ptr [edi*4 + 0x413f38]
            //   830c06ff             | or                  dword ptr [esi + eax], 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   eb16                 | jmp                 0x18
            //   e8????????           |                     

        $sequence_14 = { 8b542414 52 6a00 68ff0f1f00 ff15???????? 6804010000 }
            // n = 6, score = 100
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   68ff0f1f00           | push                0x1f0fff
            //   ff15????????         |                     
            //   6804010000           | push                0x104

        $sequence_15 = { 50 e8???????? 57 8d85f9feffff 889df8feffff }
            // n = 5, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   57                   | push                edi
            //   8d85f9feffff         | lea                 eax, [ebp - 0x107]
            //   889df8feffff         | mov                 byte ptr [ebp - 0x108], bl

        $sequence_16 = { 83c9ff bf???????? 33c0 83c420 f2ae f7d1 2bf9 }
            // n = 7, score = 100
            //   83c9ff               | or                  ecx, 0xffffffff
            //   bf????????           |                     
            //   33c0                 | xor                 eax, eax
            //   83c420               | add                 esp, 0x20
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx

        $sequence_17 = { 50 e8???????? ffb63c854000 8d8560ffffff 50 e8???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffb63c854000         | push                dword ptr [esi + 0x40853c]
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_18 = { 50 e8???????? 8d8560ffffff 68???????? 50 e8???????? ffb62c724000 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffb62c724000         | push                dword ptr [esi + 0x40722c]

        $sequence_19 = { 83c10c 3bc2 72f4 eb0c 8d0440 8b0c86 898decfdffff }
            // n = 7, score = 100
            //   83c10c               | add                 ecx, 0xc
            //   3bc2                 | cmp                 eax, edx
            //   72f4                 | jb                  0xfffffff6
            //   eb0c                 | jmp                 0xe
            //   8d0440               | lea                 eax, [eax + eax*2]
            //   8b0c86               | mov                 ecx, dword ptr [esi + eax*4]
            //   898decfdffff         | mov                 dword ptr [ebp - 0x214], ecx

        $sequence_20 = { ff15???????? 85c0 742f 8b4d0c f7d9 8d55f0 52 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742f                 | je                  0x31
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   f7d9                 | neg                 ecx
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx

        $sequence_21 = { 3a4000 003b 40 0023 d18a0688078a 46 }
            // n = 6, score = 100
            //   3a4000               | cmp                 al, byte ptr [eax]
            //   003b                 | add                 byte ptr [ebx], bh
            //   40                   | inc                 eax
            //   0023                 | add                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi

        $sequence_22 = { 50 ffd6 8b0d???????? 68???????? 51 c705????????04000000 ffd6 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   68????????           |                     
            //   51                   | push                ecx
            //   c705????????04000000     |     
            //   ffd6                 | call                esi

        $sequence_23 = { 8a8c181d010000 888808972400 40 ebe6 ff35???????? ff15???????? 85c0 }
            // n = 7, score = 100
            //   8a8c181d010000       | mov                 cl, byte ptr [eax + ebx + 0x11d]
            //   888808972400         | mov                 byte ptr [eax + 0x249708], cl
            //   40                   | inc                 eax
            //   ebe6                 | jmp                 0xffffffe8
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_24 = { 8a81a9704000 41 84c0 75f1 5e c3 8a8190704000 }
            // n = 7, score = 100
            //   8a81a9704000         | mov                 al, byte ptr [ecx + 0x4070a9]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f1                 | jne                 0xfffffff3
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8a8190704000         | mov                 al, byte ptr [ecx + 0x407090]

        $sequence_25 = { 53 56 6a01 68???????? e8???????? 6a01 68???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   6a01                 | push                1
            //   68????????           |                     
            //   e8????????           |                     
            //   6a01                 | push                1
            //   68????????           |                     

        $sequence_26 = { 740e 0fb7044562754000 23442408 eb02 33c0 }
            // n = 5, score = 100
            //   740e                 | je                  0x10
            //   0fb7044562754000     | movzx               eax, word ptr [eax*2 + 0x407562]
            //   23442408             | and                 eax, dword ptr [esp + 8]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_27 = { 8955e0 eb83 890cb5383f4100 013d???????? 8b04b5383f4100 }
            // n = 5, score = 100
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   eb83                 | jmp                 0xffffff85
            //   890cb5383f4100       | mov                 dword ptr [esi*4 + 0x413f38], ecx
            //   013d????????         |                     
            //   8b04b5383f4100       | mov                 eax, dword ptr [esi*4 + 0x413f38]

        $sequence_28 = { 894df8 ff15???????? 85c0 751d 8b45e8 }
            // n = 5, score = 100
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   751d                 | jne                 0x1f
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_29 = { 83d8ff 85c0 0f841f020000 83c9ff bf???????? 33c0 68???????? }
            // n = 7, score = 100
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   0f841f020000         | je                  0x225
            //   83c9ff               | or                  ecx, 0xffffffff
            //   bf????????           |                     
            //   33c0                 | xor                 eax, eax
            //   68????????           |                     

    condition:
        7 of them and filesize < 212992
}