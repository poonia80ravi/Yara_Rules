rule win_syscon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.syscon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.syscon"
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
        $sequence_0 = { 68???????? ffd7 a1???????? 68???????? 50 ff15???????? }
            // n = 6, score = 200
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   a1????????           |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 68???????? ffd7 68e8030000 8d8c24fc070000 6a00 51 e8???????? }
            // n = 7, score = 200
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   68e8030000           | push                0x3e8
            //   8d8c24fc070000       | lea                 ecx, [esp + 0x7fc]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_2 = { 51 68???????? ffd7 0fb60e ba???????? }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   0fb60e               | movzx               ecx, byte ptr [esi]
            //   ba????????           |                     

        $sequence_3 = { 40 50 53 68???????? ffd6 eb0c 53 }
            // n = 7, score = 200
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   53                   | push                ebx
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   eb0c                 | jmp                 0xe
            //   53                   | push                ebx

        $sequence_4 = { 83c408 56 ff15???????? 8b1d???????? 68???????? 57 ffd3 }
            // n = 7, score = 200
            //   83c408               | add                 esp, 8
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd3                 | call                ebx

        $sequence_5 = { 68???????? 50 c705????????02000000 c705????????03000000 8935???????? }
            // n = 5, score = 200
            //   68????????           |                     
            //   50                   | push                eax
            //   c705????????02000000     |     
            //   c705????????03000000     |     
            //   8935????????         |                     

        $sequence_6 = { 8d4301 50 6a40 ff15???????? 8bf0 85f6 }
            // n = 6, score = 200
            //   8d4301               | lea                 eax, [ebx + 1]
            //   50                   | push                eax
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi

        $sequence_7 = { 890d???????? 8935???????? c705????????b80b0000 c705????????10000000 8935???????? }
            // n = 5, score = 200
            //   890d????????         |                     
            //   8935????????         |                     
            //   c705????????b80b0000     |     
            //   c705????????10000000     |     
            //   8935????????         |                     

        $sequence_8 = { 664489642440 4889442442 8944244a 668944244e e8???????? 488d9508100000 488bcb }
            // n = 7, score = 100
            //   664489642440         | dec                 eax
            //   4889442442           | lea                 ecx, [ebp - 0x70]
            //   8944244a             | inc                 eax
            //   668944244e           | mov                 cl, ch
            //   e8????????           |                     
            //   488d9508100000       | dec                 esp
            //   488bcb               | mov                 ebx, eax

        $sequence_9 = { 4881ec48010000 488d4c2430 33d2 41b804010000 }
            // n = 4, score = 100
            //   4881ec48010000       | dec                 eax
            //   488d4c2430           | mov                 ecx, eax
            //   33d2                 | test                eax, eax
            //   41b804010000         | je                  0x2f2

        $sequence_10 = { 488d4c2420 4c8bc6 33d2 e8???????? 488d0da34c0000 ff15???????? 488d542420 }
            // n = 7, score = 100
            //   488d4c2420           | dec                 eax
            //   4c8bc6               | lea                 edx, [ebp + 0x420]
            //   33d2                 | dec                 eax
            //   e8????????           |                     
            //   488d0da34c0000       | lea                 ecx, [0x3290]
            //   ff15????????         |                     
            //   488d542420           | inc                 esp

        $sequence_11 = { ff15???????? 2bc3 3b85f80f0000 0f8679030000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   2bc3                 | lea                 ecx, [esp + 0x20]
            //   3b85f80f0000         | dec                 esp
            //   0f8679030000         | mov                 eax, esi

        $sequence_12 = { 488d9520040000 488d0d90320000 448bc0 e8???????? }
            // n = 4, score = 100
            //   488d9520040000       | sub                 eax, ebx
            //   488d0d90320000       | cmp                 eax, dword ptr [ebp + 0xff8]
            //   448bc0               | jbe                 0x385
            //   e8????????           |                     

        $sequence_13 = { baff010f00 488bc8 ff15???????? 85c0 0f84ea020000 488d4d90 }
            // n = 6, score = 100
            //   baff010f00           | mov                 eax, eax
            //   488bc8               | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | lea                 ecx, [esp + 0x20]
            //   0f84ea020000         | dec                 esp
            //   488d4d90             | mov                 eax, esi

        $sequence_14 = { ff15???????? 488905???????? 4885c0 0f84dbfdffff 488d4c2420 4c8bc6 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488905????????       |                     
            //   4885c0               | dec                 eax
            //   0f84dbfdffff         | test                eax, eax
            //   488d4c2420           | je                  0xfffffde1
            //   4c8bc6               | dec                 eax

        $sequence_15 = { 408acd 4c8bd8 488d05323d0000 c0e106 442ad8 418ac4 }
            // n = 6, score = 100
            //   408acd               | xor                 edx, edx
            //   4c8bd8               | dec                 eax
            //   488d05323d0000       | lea                 ecx, [0x4ca3]
            //   c0e106               | dec                 eax
            //   442ad8               | lea                 edx, [esp + 0x20]
            //   418ac4               | mov                 edx, 0xf01ff

    condition:
        7 of them and filesize < 120832
}