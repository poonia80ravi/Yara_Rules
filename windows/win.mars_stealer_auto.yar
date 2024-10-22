rule win_mars_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mars_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mars_stealer"
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
        $sequence_0 = { 837d1800 7426 8b551c 52 8b4518 50 }
            // n = 6, score = 100
            //   837d1800             | cmp                 dword ptr [ebp + 0x18], 0
            //   7426                 | je                  0x28
            //   8b551c               | mov                 edx, dword ptr [ebp + 0x1c]
            //   52                   | push                edx
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   50                   | push                eax

        $sequence_1 = { 51 8b953cfbffff 52 8b45f4 50 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   8b953cfbffff         | mov                 edx, dword ptr [ebp - 0x4c4]
            //   52                   | push                edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax

        $sequence_2 = { 8d4df4 51 ff15???????? 5f 5e 8be5 }
            // n = 6, score = 100
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp

        $sequence_3 = { 8d9550e9ffff 52 e8???????? 6804010000 8d85f0feffff 50 e8???????? }
            // n = 7, score = 100
            //   8d9550e9ffff         | lea                 edx, [ebp - 0x16b0]
            //   52                   | push                edx
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 743e 8b450c 50 8b4d18 51 }
            // n = 5, score = 100
            //   743e                 | je                  0x40
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]
            //   51                   | push                ecx

        $sequence_5 = { 837df820 0f8d61030000 6804010000 8d8de8feffff 51 }
            // n = 5, score = 100
            //   837df820             | cmp                 dword ptr [ebp - 8], 0x20
            //   0f8d61030000         | jge                 0x367
            //   6804010000           | push                0x104
            //   8d8de8feffff         | lea                 ecx, [ebp - 0x118]
            //   51                   | push                ecx

        $sequence_6 = { 55 8bec b8b8160000 e8???????? 6888130000 8d8558eaffff 50 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b8b8160000           | mov                 eax, 0x16b8
            //   e8????????           |                     
            //   6888130000           | push                0x1388
            //   8d8558eaffff         | lea                 eax, [ebp - 0x15a8]
            //   50                   | push                eax

        $sequence_7 = { 68???????? 8b0d???????? 51 ff15???????? 8b95e4fcffff 52 ff15???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b95e4fcffff         | mov                 edx, dword ptr [ebp - 0x31c]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_8 = { 6800010000 8d8de8fcffff 51 6aff 8b953cfbffff 8b4218 }
            // n = 6, score = 100
            //   6800010000           | push                0x100
            //   8d8de8fcffff         | lea                 ecx, [ebp - 0x318]
            //   51                   | push                ecx
            //   6aff                 | push                -1
            //   8b953cfbffff         | mov                 edx, dword ptr [ebp - 0x4c4]
            //   8b4218               | mov                 eax, dword ptr [edx + 0x18]

        $sequence_9 = { 50 e8???????? 6804010000 8d8db0fdffff 51 e8???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8d8db0fdffff         | lea                 ecx, [ebp - 0x250]
            //   51                   | push                ecx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 219136
}