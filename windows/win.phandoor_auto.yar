rule win_phandoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.phandoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phandoor"
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
        $sequence_0 = { 833d????????00 7467 833d????????00 745e 833d????????00 7455 }
            // n = 6, score = 800
            //   833d????????00       |                     
            //   7467                 | je                  0x69
            //   833d????????00       |                     
            //   745e                 | je                  0x60
            //   833d????????00       |                     
            //   7455                 | je                  0x57

        $sequence_1 = { e8???????? 83c404 eb25 e8???????? 8d86d8010000 83c404 }
            // n = 6, score = 800
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   eb25                 | jmp                 0x27
            //   e8????????           |                     
            //   8d86d8010000         | lea                 eax, [esi + 0x1d8]
            //   83c404               | add                 esp, 4

        $sequence_2 = { a3???????? 0f8482000000 833d????????00 7479 833d????????00 7470 833d????????00 }
            // n = 7, score = 800
            //   a3????????           |                     
            //   0f8482000000         | je                  0x88
            //   833d????????00       |                     
            //   7479                 | je                  0x7b
            //   833d????????00       |                     
            //   7470                 | je                  0x72
            //   833d????????00       |                     

        $sequence_3 = { 3bf3 0f8400010000 57 8d4900 8d45f8 50 }
            // n = 6, score = 800
            //   3bf3                 | cmp                 esi, ebx
            //   0f8400010000         | je                  0x106
            //   57                   | push                edi
            //   8d4900               | lea                 ecx, [ecx]
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_4 = { 57 68???????? 8d45f4 68???????? 50 8bf9 }
            // n = 6, score = 800
            //   57                   | push                edi
            //   68????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   68????????           |                     
            //   50                   | push                eax
            //   8bf9                 | mov                 edi, ecx

        $sequence_5 = { ffd6 833d????????00 a3???????? 0f8482000000 }
            // n = 4, score = 800
            //   ffd6                 | call                esi
            //   833d????????00       |                     
            //   a3????????           |                     
            //   0f8482000000         | je                  0x88

        $sequence_6 = { 833d????????00 0f842b010000 833d????????00 0f841e010000 }
            // n = 4, score = 800
            //   833d????????00       |                     
            //   0f842b010000         | je                  0x131
            //   833d????????00       |                     
            //   0f841e010000         | je                  0x124

        $sequence_7 = { 8b36 3bf3 0f857bffffff eb74 }
            // n = 4, score = 800
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   3bf3                 | cmp                 esi, ebx
            //   0f857bffffff         | jne                 0xffffff81
            //   eb74                 | jmp                 0x76

        $sequence_8 = { 83c102 66833e27 7510 40 }
            // n = 4, score = 500
            //   83c102               | add                 ecx, 2
            //   66833e27             | cmp                 word ptr [esi], 0x27
            //   7510                 | jne                 0x12
            //   40                   | inc                 eax

        $sequence_9 = { 33f6 8975ec 8975fc 3bde }
            // n = 4, score = 500
            //   33f6                 | xor                 esi, esi
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   3bde                 | cmp                 ebx, esi

        $sequence_10 = { 33d2 3955e4 53 0f9dc2 }
            // n = 4, score = 500
            //   33d2                 | xor                 edx, edx
            //   3955e4               | cmp                 dword ptr [ebp - 0x1c], edx
            //   53                   | push                ebx
            //   0f9dc2               | setge               dl

        $sequence_11 = { 0fb74d10 8b550c 6a01 51 }
            // n = 4, score = 500
            //   0fb74d10             | movzx               ecx, word ptr [ebp + 0x10]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   6a01                 | push                1
            //   51                   | push                ecx

        $sequence_12 = { 83c102 40 83c602 3bc7 72d4 }
            // n = 5, score = 500
            //   83c102               | add                 ecx, 2
            //   40                   | inc                 eax
            //   83c602               | add                 esi, 2
            //   3bc7                 | cmp                 eax, edi
            //   72d4                 | jb                  0xffffffd6

        $sequence_13 = { 56 e8???????? 83c404 84c0 740e }
            // n = 5, score = 500
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   84c0                 | test                al, al
            //   740e                 | je                  0x10

        $sequence_14 = { 80f95c 7510 803830 750b }
            // n = 4, score = 500
            //   80f95c               | cmp                 cl, 0x5c
            //   7510                 | jne                 0x12
            //   803830               | cmp                 byte ptr [eax], 0x30
            //   750b                 | jne                 0xd

        $sequence_15 = { 83f8ff 774b 50 52 ff15???????? }
            // n = 5, score = 500
            //   83f8ff               | cmp                 eax, -1
            //   774b                 | ja                  0x4d
            //   50                   | push                eax
            //   52                   | push                edx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 2124800
}