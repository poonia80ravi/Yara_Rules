rule win_kgh_spy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.kgh_spy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kgh_spy"
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
        $sequence_0 = { 488d8c24f0030000 ff15???????? eb69 488d1574e30000 488d8c24b0000000 ff15???????? 85c0 }
            // n = 7, score = 100
            //   488d8c24f0030000     | lea                 ecx, [0xec9d]
            //   ff15????????         |                     
            //   eb69                 | dec                 eax
            //   488d1574e30000       | mov                 dword ptr [esp + 0x20], eax
            //   488d8c24b0000000     | jne                 0x422
            //   ff15????????         |                     
            //   85c0                 | xor                 al, al

        $sequence_1 = { 488d8c24c0000000 e8???????? 4c8d8c24c0000000 4c8d8424b4000000 488d15b8e50000 }
            // n = 5, score = 100
            //   488d8c24c0000000     | mov                 dword ptr [esp + 0x40], eax
            //   e8????????           |                     
            //   4c8d8c24c0000000     | dec                 eax
            //   4c8d8424b4000000     | mov                 eax, dword ptr [esp + 0x20]
            //   488d15b8e50000       | dec                 eax

        $sequence_2 = { c3 488d0521880000 c3 4053 }
            // n = 4, score = 100
            //   c3                   | mov                 edi, eax
            //   488d0521880000       | xor                 eax, eax
            //   c3                   | mov                 ecx, 0x18
            //   4053                 | dec                 eax

        $sequence_3 = { 48c744242000000000 4c8d0d1d0c0100 4c8d05a6270100 488d1537d70000 488b8c24c8000000 ff15???????? 4889842480000000 }
            // n = 7, score = 100
            //   48c744242000000000     | jne    0x139
            //   4c8d0d1d0c0100       | xor                 eax, eax
            //   4c8d05a6270100       | jmp                 0x18d
            //   488d1537d70000       | xor                 edx, edx
            //   488b8c24c8000000     | dec                 eax
            //   ff15????????         |                     
            //   4889842480000000     | mov                 ecx, dword ptr [esp + 0x48]

        $sequence_4 = { 48894c2408 4883ec58 48c744243000000000 c744242880000000 c744242004000000 4533c9 41b803000000 }
            // n = 7, score = 100
            //   48894c2408           | jmp                 0x3e7
            //   4883ec58             | dec                 eax
            //   48c744243000000000     | lea    edx, [0xeb0b]
            //   c744242880000000     | dec                 eax
            //   c744242004000000     | mov                 ecx, dword ptr [esp + 0x20]
            //   4533c9               | dec                 eax
            //   41b803000000         | mov                 dword ptr [esp + 0x28], eax

        $sequence_5 = { ba10000000 488bc8 e8???????? 488d0598120100 }
            // n = 4, score = 100
            //   ba10000000           | mov                 edi, eax
            //   488bc8               | xor                 eax, eax
            //   e8????????           |                     
            //   488d0598120100       | mov                 ecx, 0x103

        $sequence_6 = { 8b4050 41b904000000 41b800100000 8bd0 488b4c2430 ff15???????? 488b442438 }
            // n = 7, score = 100
            //   8b4050               | mov                 ecx, dword ptr [esp + 0x30]
            //   41b904000000         | dec                 eax
            //   41b800100000         | mov                 dword ptr [eax + 0x30], ecx
            //   8bd0                 | dec                 esp
            //   488b4c2430           | mov                 eax, dword ptr [esp + 0x28]
            //   ff15????????         |                     
            //   488b442438           | dec                 eax

        $sequence_7 = { eb58 488d0d09bf0000 ff15???????? e8???????? 0fb6c0 85c0 }
            // n = 6, score = 100
            //   eb58                 | jne                 0x1a4
            //   488d0d09bf0000       | mov                 dword ptr [esp + 0x20], 0
            //   ff15????????         |                     
            //   e8????????           |                     
            //   0fb6c0               | dec                 eax
            //   85c0                 | mov                 eax, dword ptr [esp + 0x70]

        $sequence_8 = { 0f84c2010000 488d1593350000 488bcb ff15???????? 4885c0 }
            // n = 5, score = 100
            //   0f84c2010000         | mov                 ecx, dword ptr [ecx + 0x14]
            //   488d1593350000       | dec                 eax
            //   488bcb               | mov                 edx, dword ptr [esp + 0x70]
            //   ff15????????         |                     
            //   4885c0               | mov                 eax, dword ptr [eax + 0x10]

        $sequence_9 = { 4885c0 7509 488d054fbd0000 eb04 4883c014 8938 e8???????? }
            // n = 7, score = 100
            //   4885c0               | dec                 eax
            //   7509                 | lea                 ecx, [esp + 0x3f0]
            //   488d054fbd0000       | jmp                 0x1a1
            //   eb04                 | dec                 eax
            //   4883c014             | lea                 edx, [0xe374]
            //   8938                 | dec                 eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 207872
}