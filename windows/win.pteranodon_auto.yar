rule win_pteranodon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pteranodon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pteranodon"
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
        $sequence_0 = { ffd6 ffb5f8fdffff ffd6 ffb5e0fdffff e8???????? ffb5f4fdffff }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   ffb5f8fdffff         | push                dword ptr [ebp - 0x208]
            //   ffd6                 | call                esi
            //   ffb5e0fdffff         | push                dword ptr [ebp - 0x220]
            //   e8????????           |                     
            //   ffb5f4fdffff         | push                dword ptr [ebp - 0x20c]

        $sequence_1 = { 894ddc c745e074d80210 e9???????? c745e070d80210 eba2 }
            // n = 5, score = 100
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   c745e074d80210       | mov                 dword ptr [ebp - 0x20], 0x1002d874
            //   e9????????           |                     
            //   c745e070d80210       | mov                 dword ptr [ebp - 0x20], 0x1002d870
            //   eba2                 | jmp                 0xffffffa4

        $sequence_2 = { 50 68???????? 8d45c8 6a32 50 e8???????? 8d8dc8fdffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   6a32                 | push                0x32
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8dc8fdffff         | lea                 ecx, [ebp - 0x238]

        $sequence_3 = { 8b4d08 33c0 3b0cc588bf0210 7427 40 83f82d }
            // n = 6, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   3b0cc588bf0210       | cmp                 ecx, dword ptr [eax*8 + 0x1002bf88]
            //   7427                 | je                  0x29
            //   40                   | inc                 eax
            //   83f82d               | cmp                 eax, 0x2d

        $sequence_4 = { ff24855cde4000 b801000000 5d c3 b802000000 }
            // n = 5, score = 100
            //   ff24855cde4000       | jmp                 dword ptr [eax*4 + 0x40de5c]
            //   b801000000           | mov                 eax, 1
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   b802000000           | mov                 eax, 2

        $sequence_5 = { 25f0070000 660f28a040314300 660f28b8302d4300 660f54f0 660f5cc6 660f59f4 660f5cf2 }
            // n = 7, score = 100
            //   25f0070000           | and                 eax, 0x7f0
            //   660f28a040314300     | movapd              xmm4, xmmword ptr [eax + 0x433140]
            //   660f28b8302d4300     | movapd              xmm7, xmmword ptr [eax + 0x432d30]
            //   660f54f0             | andpd               xmm6, xmm0
            //   660f5cc6             | subpd               xmm0, xmm6
            //   660f59f4             | mulpd               xmm6, xmm4
            //   660f5cf2             | subpd               xmm6, xmm2

        $sequence_6 = { 8b55f4 8bca 56 8d7101 0f1f440000 }
            // n = 5, score = 100
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8bca                 | mov                 ecx, edx
            //   56                   | push                esi
            //   8d7101               | lea                 esi, [ecx + 1]
            //   0f1f440000           | nop                 dword ptr [eax + eax]

        $sequence_7 = { a1???????? 33c5 8945fc 8d45f4 50 e8???????? 83c404 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { 0f4345c0 66891407 c644070200 eb17 6a02 }
            // n = 5, score = 100
            //   0f4345c0             | cmovae              eax, dword ptr [ebp - 0x40]
            //   66891407             | mov                 word ptr [edi + eax], dx
            //   c644070200           | mov                 byte ptr [edi + eax + 2], 0
            //   eb17                 | jmp                 0x19
            //   6a02                 | push                2

        $sequence_9 = { 83e63f c1f906 6bf630 8b0c8db8690310 80643128fd 5f 5e }
            // n = 7, score = 100
            //   83e63f               | and                 esi, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bf630               | imul                esi, esi, 0x30
            //   8b0c8db8690310       | mov                 ecx, dword ptr [ecx*4 + 0x100369b8]
            //   80643128fd           | and                 byte ptr [ecx + esi + 0x28], 0xfd
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_10 = { 56 50 6a10 8d45e8 c645f800 0f57c0 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   50                   | push                eax
            //   6a10                 | push                0x10
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   c645f800             | mov                 byte ptr [ebp - 8], 0
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_11 = { e8???????? 8d8d78f8ffff e8???????? 68???????? 6a0a 6a18 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d8d78f8ffff         | lea                 ecx, [ebp - 0x788]
            //   e8????????           |                     
            //   68????????           |                     
            //   6a0a                 | push                0xa
            //   6a18                 | push                0x18

        $sequence_12 = { 8955c8 83faff 0f8441010000 8b5de8 83c9ff 2bcb 83f901 }
            // n = 7, score = 100
            //   8955c8               | mov                 dword ptr [ebp - 0x38], edx
            //   83faff               | cmp                 edx, -1
            //   0f8441010000         | je                  0x147
            //   8b5de8               | mov                 ebx, dword ptr [ebp - 0x18]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   2bcb                 | sub                 ecx, ebx
            //   83f901               | cmp                 ecx, 1

        $sequence_13 = { 8bf1 8975ec c745f000000000 c706???????? c7467090840210 c745fc00000000 8d7e10 }
            // n = 7, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c706????????         |                     
            //   c7467090840210       | mov                 dword ptr [esi + 0x70], 0x10028490
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8d7e10               | lea                 edi, [esi + 0x10]

        $sequence_14 = { 83e13f 6bc938 8b0485e0874300 80640828fe ff36 }
            // n = 5, score = 100
            //   83e13f               | and                 ecx, 0x3f
            //   6bc938               | imul                ecx, ecx, 0x38
            //   8b0485e0874300       | mov                 eax, dword ptr [eax*4 + 0x4387e0]
            //   80640828fe           | and                 byte ptr [eax + ecx + 0x28], 0xfe
            //   ff36                 | push                dword ptr [esi]

        $sequence_15 = { 681a800000 6a00 ff15???????? 85c0 793a 8b85ecfeffff 83f810 }
            // n = 7, score = 100
            //   681a800000           | push                0x801a
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   793a                 | jns                 0x3c
            //   8b85ecfeffff         | mov                 eax, dword ptr [ebp - 0x114]
            //   83f810               | cmp                 eax, 0x10

    condition:
        7 of them and filesize < 499712
}