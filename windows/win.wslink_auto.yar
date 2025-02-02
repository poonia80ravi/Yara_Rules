rule win_wslink_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.wslink."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wslink"
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
        $sequence_0 = { 7533 c74424208e000000 4c8d0d436f0b00 41b886000000 b906000000 8d5175 e8???????? }
            // n = 7, score = 100
            //   7533                 | dec                 eax
            //   c74424208e000000     | mov                 edx, eax
            //   4c8d0d436f0b00       | dec                 ecx
            //   41b886000000         | mov                 ecx, ebp
            //   b906000000           | test                eax, eax
            //   8d5175               | je                  0x16d
            //   e8????????           |                     

        $sequence_1 = { 8bc7 eb25 ba72000000 4c8d0da29e0900 c74424209d000000 8d4a9b 448d4209 }
            // n = 7, score = 100
            //   8bc7                 | sub                 esp, eax
            //   eb25                 | dec                 ebp
            //   ba72000000           | mov                 edx, eax
            //   4c8d0da29e0900       | dec                 eax
            //   c74424209d000000     | mov                 esi, ecx
            //   8d4a9b               | dec                 ebp
            //   448d4209             | test                eax, eax

        $sequence_2 = { 760a b8feffffff e9???????? 488bfe 48c1ef04 4885ff 747d }
            // n = 7, score = 100
            //   760a                 | dec                 eax
            //   b8feffffff           | mov                 ecx, edi
            //   e9????????           |                     
            //   488bfe               | mov                 ebx, eax
            //   48c1ef04             | cmp                 eax, ebx
            //   4885ff               | je                  0x13ec
            //   747d                 | dec                 eax

        $sequence_3 = { e8???????? 85c0 7526 488bcf e8???????? b910000000 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   85c0                 | inc                 ebp
            //   7526                 | xor                 edx, edx
            //   488bcf               | dec                 eax
            //   e8????????           |                     
            //   b910000000           | test                ecx, ecx

        $sequence_4 = { 8d8c8910ffffff 0fbec0 48ffc2 83c302 448d4c48d0 493bd4 0f8ff0000000 }
            // n = 7, score = 100
            //   8d8c8910ffffff       | inc                 ecx
            //   0fbec0               | mov                 eax, dword ptr [eax + 4]
            //   48ffc2               | inc                 ecx
            //   83c302               | push                esp
            //   448d4c48d0           | inc                 ecx
            //   493bd4               | push                ebp
            //   0f8ff0000000         | inc                 ecx

        $sequence_5 = { 8b7308 4d636c2408 8d5601 8bfe 412bfd 3b510c 7f05 }
            // n = 7, score = 100
            //   8b7308               | dec                 eax
            //   4d636c2408           | mov                 dword ptr [esp + 0x20], edi
            //   8d5601               | cmp                 ebx, edi
            //   8bfe                 | jle                 0x1295
            //   412bfd               | dec                 eax
            //   3b510c               | mov                 edx, dword ptr [ebp - 0x60]
            //   7f05                 | dec                 eax

        $sequence_6 = { ff15???????? 4c8d0dfa770600 8d4f26 448d476d ba8d000000 c7442420a1020000 e8???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   4c8d0dfa770600       | dec                 eax
            //   8d4f26               | imul                eax, ecx
            //   448d476d             | dec                 esp
            //   ba8d000000           | imul                ebx, edx
            //   c7442420a1020000     | dec                 eax
            //   e8????????           |                     

        $sequence_7 = { 488b5108 4889542440 4d85ff 7527 c744242032010000 4c8d0dea8e0900 ebb9 }
            // n = 7, score = 100
            //   488b5108             | dec                 ecx
            //   4889542440           | inc                 ebx
            //   4d85ff               | inc                 eax
            //   7527                 | je                  0xbf1
            //   c744242032010000     | inc                 ecx
            //   4c8d0dea8e0900       | lea                 eax, [esp + 1]
            //   ebb9                 | inc                 ecx

        $sequence_8 = { 7532 4c8d0d97450a00 8d4810 448d4008 ba9a000000 c744242048010000 e8???????? }
            // n = 7, score = 100
            //   7532                 | je                  0x202c
            //   4c8d0d97450a00       | mov                 ecx, dword ptr [eax + 8]
            //   8d4810               | dec                 eax
            //   448d4008             | mov                 dword ptr [esp + 0xd0], ebp
            //   ba9a000000           | mov                 ebp, dword ptr [eax + 0xc]
            //   c744242048010000     | dec                 esp
            //   e8????????           |                     

        $sequence_9 = { c744242033010000 e8???????? 488b4318 488bd3 488bcf 48894718 33c0 }
            // n = 7, score = 100
            //   c744242033010000     | mov                 ecx, esp
            //   e8????????           |                     
            //   488b4318             | test                eax, eax
            //   488bd3               | je                  0x35b
            //   488bcf               | dec                 eax
            //   48894718             | cmp                 dword ptr [ebx + 8], 0
            //   33c0                 | je                  0x387

    condition:
        7 of them and filesize < 2007040
}