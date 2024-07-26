rule win_makop_ransomware_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.makop_ransomware."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.makop_ransomware"
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
        $sequence_0 = { c644240f00 89742438 8974243c 89742428 }
            // n = 4, score = 100
            //   c644240f00           | mov                 byte ptr [esp + 0xf], 0
            //   89742438             | mov                 dword ptr [esp + 0x38], esi
            //   8974243c             | mov                 dword ptr [esp + 0x3c], esi
            //   89742428             | mov                 dword ptr [esp + 0x28], esi

        $sequence_1 = { 3b4c2430 0f82a3feffff 8b542414 52 ff15???????? 8b44243c }
            // n = 6, score = 100
            //   3b4c2430             | cmp                 ecx, dword ptr [esp + 0x30]
            //   0f82a3feffff         | jb                  0xfffffea9
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]

        $sequence_2 = { 807c241201 750b 8b7c2464 8b07 8b4024 eb0b }
            // n = 6, score = 100
            //   807c241201           | cmp                 byte ptr [esp + 0x12], 1
            //   750b                 | jne                 0xd
            //   8b7c2464             | mov                 edi, dword ptr [esp + 0x64]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   8b4024               | mov                 eax, dword ptr [eax + 0x24]
            //   eb0b                 | jmp                 0xd

        $sequence_3 = { 68???????? 6a00 6a00 ff15???????? 6aff 50 89442424 }
            // n = 7, score = 100
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   89442424             | mov                 dword ptr [esp + 0x24], eax

        $sequence_4 = { 6a0d e8???????? 8d542410 8bd8 a1???????? 52 6a0e }
            // n = 7, score = 100
            //   6a0d                 | push                0xd
            //   e8????????           |                     
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   8bd8                 | mov                 ebx, eax
            //   a1????????           |                     
            //   52                   | push                edx
            //   6a0e                 | push                0xe

        $sequence_5 = { 895804 8918 eb02 33c0 6a04 53 a3???????? }
            // n = 7, score = 100
            //   895804               | mov                 dword ptr [eax + 4], ebx
            //   8918                 | mov                 dword ptr [eax], ebx
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   6a04                 | push                4
            //   53                   | push                ebx
            //   a3????????           |                     

        $sequence_6 = { 8b3d???????? 56 ffd7 53 ffd5 53 897318 }
            // n = 7, score = 100
            //   8b3d????????         |                     
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   53                   | push                ebx
            //   ffd5                 | call                ebp
            //   53                   | push                ebx
            //   897318               | mov                 dword ptr [ebx + 0x18], esi

        $sequence_7 = { 8b35???????? eb02 33c0 a3???????? }
            // n = 4, score = 100
            //   8b35????????         |                     
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   a3????????           |                     

        $sequence_8 = { 6a00 50 52 55 ff15???????? 85c0 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   50                   | push                eax
            //   52                   | push                edx
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8b3d???????? 741d b980000000 8d4900 }
            // n = 4, score = 100
            //   8b3d????????         |                     
            //   741d                 | je                  0x1f
            //   b980000000           | mov                 ecx, 0x80
            //   8d4900               | lea                 ecx, [ecx]

    condition:
        7 of them and filesize < 107520
}