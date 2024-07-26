rule win_royal_dns_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.royal_dns."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_dns"
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
        $sequence_0 = { e8???????? 83c404 83bd80f1ffff05 7c12 8b8d7cf1ffff 51 ff15???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83bd80f1ffff05       | cmp                 dword ptr [ebp - 0xe80], 5
            //   7c12                 | jl                  0x14
            //   8b8d7cf1ffff         | mov                 ecx, dword ptr [ebp - 0xe84]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_1 = { 75f6 8d442448 50 6802020000 ff15???????? 85c0 }
            // n = 6, score = 100
            //   75f6                 | jne                 0xfffffff8
            //   8d442448             | lea                 eax, [esp + 0x48]
            //   50                   | push                eax
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_2 = { ffd6 a1???????? 83f803 7405 83f801 75ed 8b8c24dc020000 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   a1????????           |                     
            //   83f803               | cmp                 eax, 3
            //   7405                 | je                  7
            //   83f801               | cmp                 eax, 1
            //   75ed                 | jne                 0xffffffef
            //   8b8c24dc020000       | mov                 ecx, dword ptr [esp + 0x2dc]

        $sequence_3 = { 33c6 0fbe7102 8bf8 c1e705 03f7 8bf8 c1ef02 }
            // n = 7, score = 100
            //   33c6                 | xor                 eax, esi
            //   0fbe7102             | movsx               esi, byte ptr [ecx + 2]
            //   8bf8                 | mov                 edi, eax
            //   c1e705               | shl                 edi, 5
            //   03f7                 | add                 esi, edi
            //   8bf8                 | mov                 edi, eax
            //   c1ef02               | shr                 edi, 2

        $sequence_4 = { 51 894808 6a02 89480c bf01000000 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   6a02                 | push                2
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx
            //   bf01000000           | mov                 edi, 1

        $sequence_5 = { 51 ffd3 0fb7d0 8b4708 52 83c00c 56 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ffd3                 | call                ebx
            //   0fb7d0               | movzx               edx, ax
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   52                   | push                edx
            //   83c00c               | add                 eax, 0xc
            //   56                   | push                esi

        $sequence_6 = { 7416 83fe04 7511 8b95bff7ffff 89957cf1ffff e9???????? 85c9 }
            // n = 7, score = 100
            //   7416                 | je                  0x18
            //   83fe04               | cmp                 esi, 4
            //   7511                 | jne                 0x13
            //   8b95bff7ffff         | mov                 edx, dword ptr [ebp - 0x841]
            //   89957cf1ffff         | mov                 dword ptr [ebp - 0xe84], edx
            //   e9????????           |                     
            //   85c9                 | test                ecx, ecx

        $sequence_7 = { 8906 894604 6a0c 894608 e8???????? 8bf8 }
            // n = 6, score = 100
            //   8906                 | mov                 dword ptr [esi], eax
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   6a0c                 | push                0xc
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_8 = { 53 ffd6 8b45ec 50 ffd6 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_9 = { a4 e8???????? 8bf8 83c404 85ff }
            // n = 5, score = 100
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   85ff                 | test                edi, edi

    condition:
        7 of them and filesize < 204800
}