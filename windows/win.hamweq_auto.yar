rule win_hamweq_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hamweq."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hamweq"
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
        $sequence_0 = { 8b06 ffb1a0000000 8d8de0fdffff 51 }
            // n = 4, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ffb1a0000000         | push                dword ptr [ecx + 0xa0]
            //   8d8de0fdffff         | lea                 ecx, [ebp - 0x220]
            //   51                   | push                ecx

        $sequence_1 = { 41 51 8d4d80 51 ff5054 }
            // n = 5, score = 200
            //   41                   | inc                 ecx
            //   51                   | push                ecx
            //   8d4d80               | lea                 ecx, [ebp - 0x80]
            //   51                   | push                ecx
            //   ff5054               | call                dword ptr [eax + 0x54]

        $sequence_2 = { 8b4e08 8b06 6a03 ffb100010000 8d4dfc }
            // n = 5, score = 200
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6a03                 | push                3
            //   ffb100010000         | push                dword ptr [ecx + 0x100]
            //   8d4dfc               | lea                 ecx, [ebp - 4]

        $sequence_3 = { ffb140010000 8d8dfcfdffff 51 ff5048 8b06 8d8dfcfdffff 57 }
            // n = 7, score = 200
            //   ffb140010000         | push                dword ptr [ecx + 0x140]
            //   8d8dfcfdffff         | lea                 ecx, [ebp - 0x204]
            //   51                   | push                ecx
            //   ff5048               | call                dword ptr [eax + 0x48]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d8dfcfdffff         | lea                 ecx, [ebp - 0x204]
            //   57                   | push                edi

        $sequence_4 = { 50 8d85e4f1ffff 50 53 ff571c }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8d85e4f1ffff         | lea                 eax, [ebp - 0xe1c]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff571c               | call                dword ptr [edi + 0x1c]

        $sequence_5 = { 57 51 ff7508 ff9094000000 85c0 7424 395df8 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   51                   | push                ecx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff9094000000         | call                dword ptr [eax + 0x94]
            //   85c0                 | test                eax, eax
            //   7424                 | je                  0x26
            //   395df8               | cmp                 dword ptr [ebp - 8], ebx

        $sequence_6 = { ff5020 8b4e08 8b06 ffb180010000 8d8decfeffff 51 }
            // n = 6, score = 200
            //   ff5020               | call                dword ptr [eax + 0x20]
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ffb180010000         | push                dword ptr [ecx + 0x180]
            //   8d8decfeffff         | lea                 ecx, [ebp - 0x114]
            //   51                   | push                ecx

        $sequence_7 = { 8b06 8d8dfcfdffff 6a02 51 ff5038 8b06 }
            // n = 6, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d8dfcfdffff         | lea                 ecx, [ebp - 0x204]
            //   6a02                 | push                2
            //   51                   | push                ecx
            //   ff5038               | call                dword ptr [eax + 0x38]
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_8 = { ff7508 ff5020 8b4e08 8b06 ffb180010000 8d8decfeffff 51 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff5020               | call                dword ptr [eax + 0x20]
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ffb180010000         | push                dword ptr [ecx + 0x180]
            //   8d8decfeffff         | lea                 ecx, [ebp - 0x114]
            //   51                   | push                ecx

        $sequence_9 = { 8b06 8d8de4f1ffff 53 51 ff5048 8b06 8d8de4f1ffff }
            // n = 7, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d8de4f1ffff         | lea                 ecx, [ebp - 0xe1c]
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   ff5048               | call                dword ptr [eax + 0x48]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d8de4f1ffff         | lea                 ecx, [ebp - 0xe1c]

    condition:
        7 of them and filesize < 24576
}