rule win_anatova_ransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.anatova_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anatova_ransom"
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
        $sequence_0 = { 488d05a62c0000 488945d8 b80a000000 8845d7 b800000000 }
            // n = 5, score = 100
            //   488d05a62c0000       | jmp                 0x67
            //   488945d8             | mov                 eax, 0
            //   b80a000000           | mov                 dword ptr [ebp - 0x8c], eax
            //   8845d7               | dec                 eax
            //   b800000000           | mov                 eax, dword ptr [ebp - 0x30]

        $sequence_1 = { 488d055d2a0000 488945c8 488d05622a0000 488945d0 488d05672a0000 488945d8 488d05642a0000 }
            // n = 7, score = 100
            //   488d055d2a0000       | lea                 eax, [0x57ec]
            //   488945c8             | dec                 eax
            //   488d05622a0000       | mov                 dword ptr [ebp - 0x78], eax
            //   488945d0             | dec                 eax
            //   488d05672a0000       | lea                 eax, [0x58f2]
            //   488945d8             | dec                 eax
            //   488d05642a0000       | mov                 dword ptr [ebp - 0x48], eax

        $sequence_2 = { 488d054e300000 4989c2 4c89d1 4c89da e8???????? }
            // n = 5, score = 100
            //   488d054e300000       | mov                 eax, dword ptr [ebp - 0x6c]
            //   4989c2               | dec                 eax
            //   4c89d1               | mov                 ecx, eax
            //   4c89da               | add                 eax, 1
            //   e8????????           |                     

        $sequence_3 = { 894598 488b45f8 4989c2 4c89d1 e8???????? 8b4d98 4863c9 }
            // n = 7, score = 100
            //   894598               | dec                 eax
            //   488b45f8             | lea                 eax, [ebp - 0x22c]
            //   4989c2               | dec                 ecx
            //   4c89d1               | mov                 ebx, eax
            //   e8????????           |                     
            //   8b4d98               | inc                 ecx
            //   4863c9               | call                ebx

        $sequence_4 = { 488b85c0feffff 4883c02c 488b8db0feffff 4989cb }
            // n = 4, score = 100
            //   488b85c0feffff       | dec                 eax
            //   4883c02c             | lea                 eax, [0x65bd]
            //   488b8db0feffff       | dec                 eax
            //   4989cb               | mov                 dword ptr [ebp - 0x20], eax

        $sequence_5 = { 8908 488b4528 488b4d28 488b5520 }
            // n = 4, score = 100
            //   8908                 | mov                 dword ptr [ebp - 0xb8], eax
            //   488b4528             | dec                 eax
            //   488b4d28             | lea                 eax, [0x64a9]
            //   488b5520             | dec                 eax

        $sequence_6 = { 83fa00 0f8445000000 8b4528 c1e806 }
            // n = 4, score = 100
            //   83fa00               | dec                 eax
            //   0f8445000000         | lea                 eax, [0x3025]
            //   8b4528               | dec                 eax
            //   c1e806               | mov                 dword ptr [ebp - 0x40], eax

        $sequence_7 = { 4c89d1 e8???????? 8b8d70ffffff 4863c9 4839c1 }
            // n = 5, score = 100
            //   4c89d1               | setb                al
            //   e8????????           |                     
            //   8b8d70ffffff         | inc                 ecx
            //   4863c9               | call                ebx
            //   4839c1               | dec                 eax

        $sequence_8 = { 0fb6c0 488d052b520000 4989c2 4c89d1 }
            // n = 4, score = 100
            //   0fb6c0               | dec                 eax
            //   488d052b520000       | mov                 ecx, eax
            //   4989c2               | jge                 0x163
            //   4c89d1               | cmp                 eax, 0

        $sequence_9 = { 48b80000000000000000 4889442430 b880000000 4889442428 b801000000 4889442420 48b80000000000000000 }
            // n = 7, score = 100
            //   48b80000000000000000     | cmp    eax, 0
            //   4889442430           | je                  0x1a21
            //   b880000000           | dec                 eax
            //   4889442428           | mov                 eax, dword ptr [ebp + 0x10]
            //   b801000000           | dec                 eax
            //   4889442420           | mov                 eax, 0
            //   48b80000000000000000     | add    byte ptr [eax], al

    condition:
        7 of them and filesize < 671744
}