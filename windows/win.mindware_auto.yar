rule win_mindware_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mindware."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mindware"
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
        $sequence_0 = { c785d4e8fffff8cb4300 c785d8e8ffff00cc4300 c785dce8ffff08cc4300 c785e0e8ffff10cc4300 c785e4e8ffff18cc4300 c785e8e8ffff20cc4300 }
            // n = 6, score = 100
            //   c785d4e8fffff8cb4300     | mov    dword ptr [ebp - 0x172c], 0x43cbf8
            //   c785d8e8ffff00cc4300     | mov    dword ptr [ebp - 0x1728], 0x43cc00
            //   c785dce8ffff08cc4300     | mov    dword ptr [ebp - 0x1724], 0x43cc08
            //   c785e0e8ffff10cc4300     | mov    dword ptr [ebp - 0x1720], 0x43cc10
            //   c785e4e8ffff18cc4300     | mov    dword ptr [ebp - 0x171c], 0x43cc18
            //   c785e8e8ffff20cc4300     | mov    dword ptr [ebp - 0x1718], 0x43cc20

        $sequence_1 = { 8b5df0 33148dc0c84400 8b4de0 33501c 49 83c020 8955f8 }
            // n = 7, score = 100
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   33148dc0c84400       | xor                 edx, dword ptr [ecx*4 + 0x44c8c0]
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   33501c               | xor                 edx, dword ptr [eax + 0x1c]
            //   49                   | dec                 ecx
            //   83c020               | add                 eax, 0x20
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_2 = { c78554fbffff4cfa4300 c78558fbffff54fa4300 c7855cfbffff5cfa4300 c78560fbffff64fa4300 c78564fbffff6cfa4300 c78568fbffff74fa4300 c7856cfbffff7cfa4300 }
            // n = 7, score = 100
            //   c78554fbffff4cfa4300     | mov    dword ptr [ebp - 0x4ac], 0x43fa4c
            //   c78558fbffff54fa4300     | mov    dword ptr [ebp - 0x4a8], 0x43fa54
            //   c7855cfbffff5cfa4300     | mov    dword ptr [ebp - 0x4a4], 0x43fa5c
            //   c78560fbffff64fa4300     | mov    dword ptr [ebp - 0x4a0], 0x43fa64
            //   c78564fbffff6cfa4300     | mov    dword ptr [ebp - 0x49c], 0x43fa6c
            //   c78568fbffff74fa4300     | mov    dword ptr [ebp - 0x498], 0x43fa74
            //   c7856cfbffff7cfa4300     | mov    dword ptr [ebp - 0x494], 0x43fa7c

        $sequence_3 = { c78548e7fffff0c74300 c7854ce7fffff8c74300 c78550e7ffff00c84300 c78554e7ffff08c84300 c78558e7ffff10c84300 c7855ce7ffff18c84300 c78560e7ffff20c84300 }
            // n = 7, score = 100
            //   c78548e7fffff0c74300     | mov    dword ptr [ebp - 0x18b8], 0x43c7f0
            //   c7854ce7fffff8c74300     | mov    dword ptr [ebp - 0x18b4], 0x43c7f8
            //   c78550e7ffff00c84300     | mov    dword ptr [ebp - 0x18b0], 0x43c800
            //   c78554e7ffff08c84300     | mov    dword ptr [ebp - 0x18ac], 0x43c808
            //   c78558e7ffff10c84300     | mov    dword ptr [ebp - 0x18a8], 0x43c810
            //   c7855ce7ffff18c84300     | mov    dword ptr [ebp - 0x18a4], 0x43c818
            //   c78560e7ffff20c84300     | mov    dword ptr [ebp - 0x18a0], 0x43c820

        $sequence_4 = { 8d85f8fdffff 50 8b4d10 51 e8???????? }
            // n = 5, score = 100
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_5 = { 660f1345c8 6a00 6880000000 6a03 6a00 6a00 }
            // n = 6, score = 100
            //   660f1345c8           | movlpd              qword ptr [ebp - 0x38], xmm0
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_6 = { 0fb6c9 8b5004 c1e308 0fb689f0d84400 33d9 8b480c 3318 }
            // n = 7, score = 100
            //   0fb6c9               | movzx               ecx, cl
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   c1e308               | shl                 ebx, 8
            //   0fb689f0d84400       | movzx               ecx, byte ptr [ecx + 0x44d8f0]
            //   33d9                 | xor                 ebx, ecx
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   3318                 | xor                 ebx, dword ptr [eax]

        $sequence_7 = { 83c40c 8b55fc 52 e8???????? 8b45fc 8b4828 894db8 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4828               | mov                 ecx, dword ptr [eax + 0x28]
            //   894db8               | mov                 dword ptr [ebp - 0x48], ecx

        $sequence_8 = { 330c8520384400 330c95e03c4400 8bd3 33f1 c1ca04 33975c010000 }
            // n = 6, score = 100
            //   330c8520384400       | xor                 ecx, dword ptr [eax*4 + 0x443820]
            //   330c95e03c4400       | xor                 ecx, dword ptr [edx*4 + 0x443ce0]
            //   8bd3                 | mov                 edx, ebx
            //   33f1                 | xor                 esi, ecx
            //   c1ca04               | ror                 edx, 4
            //   33975c010000         | xor                 edx, dword ptr [edi + 0x15c]

        $sequence_9 = { 83c201 8955fc 837dfc04 7d12 8b45fc 8b4d08 8b1481 }
            // n = 7, score = 100
            //   83c201               | add                 edx, 1
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   837dfc04             | cmp                 dword ptr [ebp - 4], 4
            //   7d12                 | jge                 0x14
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b1481               | mov                 edx, dword ptr [ecx + eax*4]

    condition:
        7 of them and filesize < 661504
}