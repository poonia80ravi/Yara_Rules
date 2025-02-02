rule win_royalcli_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.royalcli."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royalcli"
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
        $sequence_0 = { 75f8 e9???????? 6a01 68???????? 56 }
            // n = 5, score = 100
            //   75f8                 | jne                 0xfffffffa
            //   e9????????           |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_1 = { 8855e5 0fb65c05e6 305de6 0fb65c05e7 305de7 83f810 7cda }
            // n = 7, score = 100
            //   8855e5               | mov                 byte ptr [ebp - 0x1b], dl
            //   0fb65c05e6           | movzx               ebx, byte ptr [ebp + eax - 0x1a]
            //   305de6               | xor                 byte ptr [ebp - 0x1a], bl
            //   0fb65c05e7           | movzx               ebx, byte ptr [ebp + eax - 0x19]
            //   305de7               | xor                 byte ptr [ebp - 0x19], bl
            //   83f810               | cmp                 eax, 0x10
            //   7cda                 | jl                  0xffffffdc

        $sequence_2 = { c78554f7ffff00000000 85db 0f8456080000 833a00 0f844d080000 83bd7cf7ffff00 7566 }
            // n = 7, score = 100
            //   c78554f7ffff00000000     | mov    dword ptr [ebp - 0x8ac], 0
            //   85db                 | test                ebx, ebx
            //   0f8456080000         | je                  0x85c
            //   833a00               | cmp                 dword ptr [edx], 0
            //   0f844d080000         | je                  0x853
            //   83bd7cf7ffff00       | cmp                 dword ptr [ebp - 0x884], 0
            //   7566                 | jne                 0x68

        $sequence_3 = { 50 8d459c 56 50 e8???????? 8bc6 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_4 = { 50 66898df4f6ffff c785fcf6ffff0c000000 66899504f7ffff ffd7 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   66898df4f6ffff       | mov                 word ptr [ebp - 0x90c], cx
            //   c785fcf6ffff0c000000     | mov    dword ptr [ebp - 0x904], 0xc
            //   66899504f7ffff       | mov                 word ptr [ebp - 0x8fc], dx
            //   ffd7                 | call                edi

        $sequence_5 = { 52 8d45d4 50 68???????? 68???????? ff15???????? 8b8db8f9ffff }
            // n = 7, score = 100
            //   52                   | push                edx
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b8db8f9ffff         | mov                 ecx, dword ptr [ebp - 0x648]

        $sequence_6 = { c1e006 03048dc04b4100 eb02 8bc2 f6402480 0f8571ffffff 33f6 }
            // n = 7, score = 100
            //   c1e006               | shl                 eax, 6
            //   03048dc04b4100       | add                 eax, dword ptr [ecx*4 + 0x414bc0]
            //   eb02                 | jmp                 4
            //   8bc2                 | mov                 eax, edx
            //   f6402480             | test                byte ptr [eax + 0x24], 0x80
            //   0f8571ffffff         | jne                 0xffffff77
            //   33f6                 | xor                 esi, esi

        $sequence_7 = { 40 84c9 75f6 5f 5e 8b4dfc }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f6                 | jne                 0xfffffff8
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_8 = { 68???????? 50 e8???????? 8bf0 83c408 85f6 7438 }
            // n = 7, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   7438                 | je                  0x3a

        $sequence_9 = { eb02 33c0 0fbe84c150f24000 6a07 }
            // n = 4, score = 100
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   0fbe84c150f24000     | movsx               eax, byte ptr [ecx + eax*8 + 0x40f250]
            //   6a07                 | push                7

    condition:
        7 of them and filesize < 204800
}