rule win_nimrev_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.nimrev."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimrev"
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
        $sequence_0 = { 01d0 01c0 29c1 89c8 83c030 89c1 }
            // n = 6, score = 200
            //   01d0                 | mov                 dword ptr [ebp - 0x10], 0x423c34
            //   01c0                 | mov                 eax, dword ptr [eax]
            //   29c1                 | cmp                 eax, 7
            //   89c8                 | ja                  0x15c0
            //   83c030               | mov                 dword ptr [ebp - 0x14], 0xca
            //   89c1                 | mov                 dword ptr [ebp - 0x10], 0x42216f

        $sequence_1 = { 0fb600 0fbec0 89c1 e8???????? }
            // n = 4, score = 200
            //   0fb600               | mov                 byte ptr [ebp - 0x3e], al
            //   0fbec0               | jmp                 0x5e
            //   89c1                 | nop                 
            //   e8????????           |                     

        $sequence_2 = { 8845ef eb01 90 807def00 }
            // n = 4, score = 200
            //   8845ef               | dec                 eax
            //   eb01                 | mov                 dword ptr [ebp - 0x38], 0
            //   90                   | dec                 eax
            //   807def00             | mov                 dword ptr [ebp - 0x60], 0x42

        $sequence_3 = { 7508 90 e8???????? eb01 }
            // n = 4, score = 200
            //   7508                 | dec                 eax
            //   90                   | lea                 eax, [0x2d746]
            //   e8????????           |                     
            //   eb01                 | dec                 eax

        $sequence_4 = { 663dd007 7507 e8???????? eb01 90 90 }
            // n = 6, score = 200
            //   663dd007             | mov                 dword ptr [ebp - 8], eax
            //   7507                 | dec                 eax
            //   e8????????           |                     
            //   eb01                 | mov                 eax, dword ptr [ebp - 8]
            //   90                   | dec                 eax
            //   90                   | mov                 ecx, eax

        $sequence_5 = { e8???????? e8???????? eb04 90 eb01 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   e8????????           |                     
            //   eb04                 | mov                 dword ptr [ebp - 0x30], 0
            //   90                   | mov                 dword ptr [ebp - 0x3c], ecx
            //   eb01                 | mov                 dword ptr [ebp - 0x40], edx

        $sequence_6 = { 01d0 01c0 29c1 89c8 83c030 }
            // n = 5, score = 200
            //   01d0                 | dec                 eax
            //   01c0                 | cmp                 dword ptr [ebp + 0x18], 0
            //   29c1                 | je                  0xf96
            //   89c8                 | dec                 eax
            //   83c030               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_7 = { eb01 90 e8???????? 90 }
            // n = 4, score = 200
            //   eb01                 | mov                 dword ptr [ebp - 0x14], 0x422b17
            //   90                   | mov                 eax, dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   90                   | mov                 dword ptr [esp + 4], eax

        $sequence_8 = { 0f9ec0 8845ef eb01 90 }
            // n = 4, score = 200
            //   0f9ec0               | nop                 
            //   8845ef               | sete                al
            //   eb01                 | mov                 byte ptr [ebp + 0x67], al
            //   90                   | jmp                 0xe1

        $sequence_9 = { 89c1 e8???????? 8945f0 c745ec00000000 }
            // n = 4, score = 200
            //   89c1                 | mov                 eax, dword ptr [ebp + 0x168]
            //   e8????????           |                     
            //   8945f0               | dec                 eax
            //   c745ec00000000       | mov                 ecx, eax

    condition:
        7 of them and filesize < 1141760
}