rule win_fast_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.fast_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fast_pos"
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
        $sequence_0 = { 85c9 7f08 8b0a 52 8b01 ff5004 57 }
            // n = 7, score = 1000
            //   85c9                 | test                ecx, ecx
            //   7f08                 | jg                  0xa
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   52                   | push                edx
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5004               | call                dword ptr [eax + 4]
            //   57                   | push                edi

        $sequence_1 = { 7ecf eb33 8b49f0 85c9 7409 8b01 ff5010 }
            // n = 7, score = 1000
            //   7ecf                 | jle                 0xffffffd1
            //   eb33                 | jmp                 0x35
            //   8b49f0               | mov                 ecx, dword ptr [ecx - 0x10]
            //   85c9                 | test                ecx, ecx
            //   7409                 | je                  0xb
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5010               | call                dword ptr [eax + 0x10]

        $sequence_2 = { ff15???????? 50 ff36 8d85e0feffff }
            // n = 4, score = 1000
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff36                 | push                dword ptr [esi]
            //   8d85e0feffff         | lea                 eax, [ebp - 0x120]

        $sequence_3 = { 6a00 6a00 68???????? ffb5e8feffff ff15???????? 85c0 7517 }
            // n = 7, score = 1000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   ffb5e8feffff         | push                dword ptr [ebp - 0x118]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19

        $sequence_4 = { 8b95e4feffff 83f8ff 8bcf 0f9585ebfeffff 83c2f0 8d420c }
            // n = 6, score = 1000
            //   8b95e4feffff         | mov                 edx, dword ptr [ebp - 0x11c]
            //   83f8ff               | cmp                 eax, -1
            //   8bcf                 | mov                 ecx, edi
            //   0f9585ebfeffff       | setne               byte ptr [ebp - 0x115]
            //   83c2f0               | add                 edx, -0x10
            //   8d420c               | lea                 eax, [edx + 0xc]

        $sequence_5 = { 83c40c e8???????? 8bc8 33c0 85c9 0f95c0 85c0 }
            // n = 7, score = 1000
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   33c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx
            //   0f95c0               | setne               al
            //   85c0                 | test                eax, eax

        $sequence_6 = { 6a01 6a00 68???????? 6802000080 c785e0feffff01000000 }
            // n = 5, score = 1000
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   c785e0feffff01000000     | mov    dword ptr [ebp - 0x120], 1

        $sequence_7 = { c785e4feffff04010000 ff15???????? e8???????? 8bc8 }
            // n = 4, score = 1000
            //   c785e4feffff04010000     | mov    dword ptr [ebp - 0x11c], 0x104
            //   ff15????????         |                     
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { 8bf9 85f6 792b 33f6 8b0f 8b41f4 }
            // n = 6, score = 1000
            //   8bf9                 | mov                 edi, ecx
            //   85f6                 | test                esi, esi
            //   792b                 | jns                 0x2d
            //   33f6                 | xor                 esi, esi
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b41f4               | mov                 eax, dword ptr [ecx - 0xc]

        $sequence_9 = { 8bf1 c745fc00000000 89b5dcfeffff c785e0feffff00000000 e8???????? }
            // n = 5, score = 1000
            //   8bf1                 | mov                 esi, ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   89b5dcfeffff         | mov                 dword ptr [ebp - 0x124], esi
            //   c785e0feffff00000000     | mov    dword ptr [ebp - 0x120], 0
            //   e8????????           |                     

    condition:
        7 of them and filesize < 327680
}