rule win_knot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.knot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.knot"
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
        $sequence_0 = { 50 ff15???????? 83f801 7517 8b4d08 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83f801               | cmp                 eax, 1
            //   7517                 | jne                 0x19
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_1 = { 0f84b9010000 c7857cf7ffff00000000 eb0f 8b8d7cf7ffff 83c101 898d7cf7ffff }
            // n = 6, score = 200
            //   0f84b9010000         | je                  0x1bf
            //   c7857cf7ffff00000000     | mov    dword ptr [ebp - 0x884], 0
            //   eb0f                 | jmp                 0x11
            //   8b8d7cf7ffff         | mov                 ecx, dword ptr [ebp - 0x884]
            //   83c101               | add                 ecx, 1
            //   898d7cf7ffff         | mov                 dword ptr [ebp - 0x884], ecx

        $sequence_2 = { 8b85d4feffff 50 e8???????? 8985d0feffff e9???????? 8b8dd4feffff }
            // n = 6, score = 200
            //   8b85d4feffff         | mov                 eax, dword ptr [ebp - 0x12c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8985d0feffff         | mov                 dword ptr [ebp - 0x130], eax
            //   e9????????           |                     
            //   8b8dd4feffff         | mov                 ecx, dword ptr [ebp - 0x12c]

        $sequence_3 = { 6a00 6a00 6a02 6a00 8b4df8 51 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx

        $sequence_4 = { 81c2e8030000 52 8d95f0fdffff 52 68???????? 8d85f0f9ffff }
            // n = 6, score = 200
            //   81c2e8030000         | add                 edx, 0x3e8
            //   52                   | push                edx
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   52                   | push                edx
            //   68????????           |                     
            //   8d85f0f9ffff         | lea                 eax, [ebp - 0x610]

        $sequence_5 = { e9???????? 8d95f4fdffff 52 8d8580f7ffff 50 }
            // n = 5, score = 200
            //   e9????????           |                     
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]
            //   52                   | push                edx
            //   8d8580f7ffff         | lea                 eax, [ebp - 0x880]
            //   50                   | push                eax

        $sequence_6 = { 8985d4fdffff 83bdd4fdffff00 7443 8b85d8fdffff }
            // n = 4, score = 200
            //   8985d4fdffff         | mov                 dword ptr [ebp - 0x22c], eax
            //   83bdd4fdffff00       | cmp                 dword ptr [ebp - 0x22c], 0
            //   7443                 | je                  0x45
            //   8b85d8fdffff         | mov                 eax, dword ptr [ebp - 0x228]

        $sequence_7 = { 83c101 898d7cf7ffff 83bd7cf7ffff12 732a 8b957cf7ffff 8b049510504000 }
            // n = 6, score = 200
            //   83c101               | add                 ecx, 1
            //   898d7cf7ffff         | mov                 dword ptr [ebp - 0x884], ecx
            //   83bd7cf7ffff12       | cmp                 dword ptr [ebp - 0x884], 0x12
            //   732a                 | jae                 0x2c
            //   8b957cf7ffff         | mov                 edx, dword ptr [ebp - 0x884]
            //   8b049510504000       | mov                 eax, dword ptr [edx*4 + 0x405010]

        $sequence_8 = { 50 8b8df0feffff 51 ff15???????? 6a3e 8d95f8feffff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8b8df0feffff         | mov                 ecx, dword ptr [ebp - 0x110]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   6a3e                 | push                0x3e
            //   8d95f8feffff         | lea                 edx, [ebp - 0x108]

        $sequence_9 = { 50 6804010000 8d8dccfbffff 51 ff15???????? 85c0 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   6804010000           | push                0x104
            //   8d8dccfbffff         | lea                 ecx, [ebp - 0x434]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 59392
}