rule win_taidoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.taidoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taidoor"
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
        $sequence_0 = { 99 b940420f00 f7f9 8d45f8 }
            // n = 4, score = 300
            //   99                   | cdq                 
            //   b940420f00           | mov                 ecx, 0xf4240
            //   f7f9                 | idiv                ecx
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_1 = { 89bde8feffff e8???????? 8b4508 8d8de8feffff }
            // n = 4, score = 300
            //   89bde8feffff         | mov                 dword ptr [ebp - 0x118], edi
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d8de8feffff         | lea                 ecx, [ebp - 0x118]

        $sequence_2 = { 897df0 50 56 e8???????? 8b3d???????? 83f86f 750c }
            // n = 7, score = 300
            //   897df0               | mov                 dword ptr [ebp - 0x10], edi
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   83f86f               | cmp                 eax, 0x6f
            //   750c                 | jne                 0xe

        $sequence_3 = { 50 53 c7458844000000 c745b401010000 66895db8 897dc4 897dc8 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   53                   | push                ebx
            //   c7458844000000       | mov                 dword ptr [ebp - 0x78], 0x44
            //   c745b401010000       | mov                 dword ptr [ebp - 0x4c], 0x101
            //   66895db8             | mov                 word ptr [ebp - 0x48], bx
            //   897dc4               | mov                 dword ptr [ebp - 0x3c], edi
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi

        $sequence_4 = { 57 a0???????? c745fc01000000 8ac8 f6d9 1bc9 33db }
            // n = 7, score = 300
            //   57                   | push                edi
            //   a0????????           |                     
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8ac8                 | mov                 cl, al
            //   f6d9                 | neg                 cl
            //   1bc9                 | sbb                 ecx, ecx
            //   33db                 | xor                 ebx, ebx

        $sequence_5 = { 50 56 e8???????? 8b3d???????? 83f86f }
            // n = 5, score = 300
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   83f86f               | cmp                 eax, 0x6f

        $sequence_6 = { 7504 c645ec30 ff75ec 8d4df0 e8???????? }
            // n = 5, score = 300
            //   7504                 | jne                 6
            //   c645ec30             | mov                 byte ptr [ebp - 0x14], 0x30
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   e8????????           |                     

        $sequence_7 = { 8bec b814130000 e8???????? 53 }
            // n = 4, score = 300
            //   8bec                 | mov                 ebp, esp
            //   b814130000           | mov                 eax, 0x1314
            //   e8????????           |                     
            //   53                   | push                ebx

        $sequence_8 = { b940420f00 f7f9 8d45e0 52 ff35???????? ff35???????? }
            // n = 6, score = 300
            //   b940420f00           | mov                 ecx, 0xf4240
            //   f7f9                 | idiv                ecx
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   52                   | push                edx
            //   ff35????????         |                     
            //   ff35????????         |                     

        $sequence_9 = { 6a02 6a30 57 ff15???????? 85c0 7504 33c0 }
            // n = 7, score = 300
            //   6a02                 | push                2
            //   6a30                 | push                0x30
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 49152
}