rule win_mole_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mole."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mole"
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
        $sequence_0 = { 40 83f817 72f1 33c0 5d c3 8b04c544ac4100 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   83f817               | cmp                 eax, 0x17
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c544ac4100       | mov                 eax, dword ptr [eax*8 + 0x41ac44]

        $sequence_1 = { 0f84d4290000 81bdf0fdffffc12bd405 0f842a500000 e9???????? }
            // n = 4, score = 100
            //   0f84d4290000         | je                  0x29da
            //   81bdf0fdffffc12bd405     | cmp    dword ptr [ebp - 0x210], 0x5d42bc1
            //   0f842a500000         | je                  0x5030
            //   e9????????           |                     

        $sequence_2 = { 8995f0fdffff 81bdf0fdffffed000000 0f877d510000 8b85f0fdffff 0fb68824d04000 ff248dfccf4000 }
            // n = 6, score = 100
            //   8995f0fdffff         | mov                 dword ptr [ebp - 0x210], edx
            //   81bdf0fdffffed000000     | cmp    dword ptr [ebp - 0x210], 0xed
            //   0f877d510000         | ja                  0x5183
            //   8b85f0fdffff         | mov                 eax, dword ptr [ebp - 0x210]
            //   0fb68824d04000       | movzx               ecx, byte ptr [eax + 0x40d024]
            //   ff248dfccf4000       | jmp                 dword ptr [ecx*4 + 0x40cffc]

        $sequence_3 = { c785b0e4ffff00000000 8b4508 8985b0e4ffff 8b8db0e4ffff 51 8d95fcf8ffff }
            // n = 6, score = 100
            //   c785b0e4ffff00000000     | mov    dword ptr [ebp - 0x1b50], 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8985b0e4ffff         | mov                 dword ptr [ebp - 0x1b50], eax
            //   8b8db0e4ffff         | mov                 ecx, dword ptr [ebp - 0x1b50]
            //   51                   | push                ecx
            //   8d95fcf8ffff         | lea                 edx, [ebp - 0x704]

        $sequence_4 = { 81bdf0fdffffcca0d105 0f84bd670000 e9???????? 81bdf0fdffffd8a0d105 0f84f26d0000 81bdf0fdffff32a1d105 0f8458610000 }
            // n = 7, score = 100
            //   81bdf0fdffffcca0d105     | cmp    dword ptr [ebp - 0x210], 0x5d1a0cc
            //   0f84bd670000         | je                  0x67c3
            //   e9????????           |                     
            //   81bdf0fdffffd8a0d105     | cmp    dword ptr [ebp - 0x210], 0x5d1a0d8
            //   0f84f26d0000         | je                  0x6df8
            //   81bdf0fdffff32a1d105     | cmp    dword ptr [ebp - 0x210], 0x5d1a132
            //   0f8458610000         | je                  0x615e

        $sequence_5 = { 8d8570efffff 50 e8???????? 83c40c 8d8d70efffff 51 }
            // n = 6, score = 100
            //   8d8570efffff         | lea                 eax, [ebp - 0x1090]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8d70efffff         | lea                 ecx, [ebp - 0x1090]
            //   51                   | push                ecx

        $sequence_6 = { 33c5 8945fc 6a01 ff15???????? 8b4510 50 ff15???????? }
            // n = 7, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { 0f8478140000 e9???????? 81bdf0fdffff3166b289 0f8441220000 81bdf0fdffffa561b389 0f840d2d0000 e9???????? }
            // n = 7, score = 100
            //   0f8478140000         | je                  0x147e
            //   e9????????           |                     
            //   81bdf0fdffff3166b289     | cmp    dword ptr [ebp - 0x210], 0x89b26631
            //   0f8441220000         | je                  0x2247
            //   81bdf0fdffffa561b389     | cmp    dword ptr [ebp - 0x210], 0x89b361a5
            //   0f840d2d0000         | je                  0x2d13
            //   e9????????           |                     

        $sequence_8 = { 83bde8feffff02 750c c785dcfeffff07000000 eb46 83bde4feffff06 7515 83bde8feffff03 }
            // n = 7, score = 100
            //   83bde8feffff02       | cmp                 dword ptr [ebp - 0x118], 2
            //   750c                 | jne                 0xe
            //   c785dcfeffff07000000     | mov    dword ptr [ebp - 0x124], 7
            //   eb46                 | jmp                 0x48
            //   83bde4feffff06       | cmp                 dword ptr [ebp - 0x11c], 6
            //   7515                 | jne                 0x17
            //   83bde8feffff03       | cmp                 dword ptr [ebp - 0x118], 3

        $sequence_9 = { 33c0 3b0cc540ac4100 740a 40 83f817 72f1 33c0 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   3b0cc540ac4100       | cmp                 ecx, dword ptr [eax*8 + 0x41ac40]
            //   740a                 | je                  0xc
            //   40                   | inc                 eax
            //   83f817               | cmp                 eax, 0x17
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 297984
}