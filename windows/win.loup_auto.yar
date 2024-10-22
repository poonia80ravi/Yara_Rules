rule win_loup_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.loup."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.loup"
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
        $sequence_0 = { 89560c ba04000000 6bc200 8b4c05e0 894dd8 0fb655df 85d2 }
            // n = 7, score = 100
            //   89560c               | mov                 dword ptr [esi + 0xc], edx
            //   ba04000000           | mov                 edx, 4
            //   6bc200               | imul                eax, edx, 0
            //   8b4c05e0             | mov                 ecx, dword ptr [ebp + eax - 0x20]
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx
            //   0fb655df             | movzx               edx, byte ptr [ebp - 0x21]
            //   85d2                 | test                edx, edx

        $sequence_1 = { ffd6 83c420 85c0 0f844e020000 }
            // n = 4, score = 100
            //   ffd6                 | call                esi
            //   83c420               | add                 esp, 0x20
            //   85c0                 | test                eax, eax
            //   0f844e020000         | je                  0x254

        $sequence_2 = { ff3485647b4100 50 e8???????? 83c410 84c0 0f8527010000 }
            // n = 6, score = 100
            //   ff3485647b4100       | push                dword ptr [eax*4 + 0x417b64]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   84c0                 | test                al, al
            //   0f8527010000         | jne                 0x12d

        $sequence_3 = { 8945f8 8b4dfc 51 8b55f8 52 6a00 68???????? }
            // n = 7, score = 100
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_4 = { c78594feffff01000000 eb0a c78594feffff00000000 8b8594feffff 52 8bcd }
            // n = 6, score = 100
            //   c78594feffff01000000     | mov    dword ptr [ebp - 0x16c], 1
            //   eb0a                 | jmp                 0xc
            //   c78594feffff00000000     | mov    dword ptr [ebp - 0x16c], 0
            //   8b8594feffff         | mov                 eax, dword ptr [ebp - 0x16c]
            //   52                   | push                edx
            //   8bcd                 | mov                 ecx, ebp

        $sequence_5 = { 85c0 0f8444030000 ff751c ff7518 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   0f8444030000         | je                  0x34a
            //   ff751c               | push                dword ptr [ebp + 0x1c]
            //   ff7518               | push                dword ptr [ebp + 0x18]

        $sequence_6 = { a1???????? 8945f4 837df4ff 7526 8b4d08 }
            // n = 5, score = 100
            //   a1????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df4ff             | cmp                 dword ptr [ebp - 0xc], -1
            //   7526                 | jne                 0x28
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_7 = { d1e2 8b4415f0 25000003d0 3d000003d0 753b 8b4dcc 8b55d0 }
            // n = 7, score = 100
            //   d1e2                 | shl                 edx, 1
            //   8b4415f0             | mov                 eax, dword ptr [ebp + edx - 0x10]
            //   25000003d0           | and                 eax, 0xd0030000
            //   3d000003d0           | cmp                 eax, 0xd0030000
            //   753b                 | jne                 0x3d
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]

        $sequence_8 = { 53 56 57 8dbd7cf9ffff b9a1010000 b8cccccccc }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8dbd7cf9ffff         | lea                 edi, [ebp - 0x684]
            //   b9a1010000           | mov                 ecx, 0x1a1
            //   b8cccccccc           | mov                 eax, 0xcccccccc

        $sequence_9 = { c1e100 8b540de0 81f247656e75 b804000000 6bc803 }
            // n = 5, score = 100
            //   c1e100               | shl                 ecx, 0
            //   8b540de0             | mov                 edx, dword ptr [ebp + ecx - 0x20]
            //   81f247656e75         | xor                 edx, 0x756e6547
            //   b804000000           | mov                 eax, 4
            //   6bc803               | imul                ecx, eax, 3

    condition:
        7 of them and filesize < 257024
}