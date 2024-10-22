rule win_xfscashncr_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.xfscashncr."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfscashncr"
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
        $sequence_0 = { 0f84a2010000 6a03 8d4dd0 51 8b550c 8b02 50 }
            // n = 7, score = 100
            //   0f84a2010000         | je                  0x1a8
            //   6a03                 | push                3
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   51                   | push                ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   50                   | push                eax

        $sequence_1 = { 8b4de4 034de8 3b4d0c 7d3d 8b55e4 0355e8 8b4508 }
            // n = 7, score = 100
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   034de8               | add                 ecx, dword ptr [ebp - 0x18]
            //   3b4d0c               | cmp                 ecx, dword ptr [ebp + 0xc]
            //   7d3d                 | jge                 0x3f
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   0355e8               | add                 edx, dword ptr [ebp - 0x18]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 3bc8 7517 8b4d94 c6012d 8b5594 83c201 895594 }
            // n = 7, score = 100
            //   3bc8                 | cmp                 ecx, eax
            //   7517                 | jne                 0x19
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]
            //   c6012d               | mov                 byte ptr [ecx], 0x2d
            //   8b5594               | mov                 edx, dword ptr [ebp - 0x6c]
            //   83c201               | add                 edx, 1
            //   895594               | mov                 dword ptr [ebp - 0x6c], edx

        $sequence_3 = { 8b4804 51 8b10 52 8d85c8feffff 50 8b4dbc }
            // n = 7, score = 100
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   51                   | push                ecx
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   52                   | push                edx
            //   8d85c8feffff         | lea                 eax, [ebp - 0x138]
            //   50                   | push                eax
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]

        $sequence_4 = { c745fcffffffff 8d4dc4 e8???????? 52 8bcd 50 8d15d8bd4700 }
            // n = 7, score = 100
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]
            //   e8????????           |                     
            //   52                   | push                edx
            //   8bcd                 | mov                 ecx, ebp
            //   50                   | push                eax
            //   8d15d8bd4700         | lea                 edx, [0x47bdd8]

        $sequence_5 = { 750b 0fb68d7fffffff 85c9 7509 8b550c 899578ffffff 8b8578ffffff }
            // n = 7, score = 100
            //   750b                 | jne                 0xd
            //   0fb68d7fffffff       | movzx               ecx, byte ptr [ebp - 0x81]
            //   85c9                 | test                ecx, ecx
            //   7509                 | jne                 0xb
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   899578ffffff         | mov                 dword ptr [ebp - 0x88], edx
            //   8b8578ffffff         | mov                 eax, dword ptr [ebp - 0x88]

        $sequence_6 = { e8???????? 668b08 0fb7d1 52 8d45d4 50 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   668b08               | mov                 cx, word ptr [eax]
            //   0fb7d1               | movzx               edx, cx
            //   52                   | push                edx
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { e8???????? 83c414 8b4d0c 51 8b55f8 52 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx

        $sequence_8 = { 0345e8 0fbe4801 83f958 7509 8b45e8 83c002 8945e8 }
            // n = 7, score = 100
            //   0345e8               | add                 eax, dword ptr [ebp - 0x18]
            //   0fbe4801             | movsx               ecx, byte ptr [eax + 1]
            //   83f958               | cmp                 ecx, 0x58
            //   7509                 | jne                 0xb
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83c002               | add                 eax, 2
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_9 = { 8b4514 8b4d0c 8908 8b5520 8b4518 8902 b801000000 }
            // n = 7, score = 100
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b5520               | mov                 edx, dword ptr [ebp + 0x20]
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   8902                 | mov                 dword ptr [edx], eax
            //   b801000000           | mov                 eax, 1

    condition:
        7 of them and filesize < 3126272
}