rule win_penco_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.penco."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.penco"
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
        $sequence_0 = { 8d9584feffff 52 8b45e4 50 ff15???????? 68???????? }
            // n = 6, score = 100
            //   8d9584feffff         | lea                 edx, [ebp - 0x17c]
            //   52                   | push                edx
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_1 = { 51 ff15???????? 898594fdffff 83bd94fdffff00 7505 e9???????? }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   898594fdffff         | mov                 dword ptr [ebp - 0x26c], eax
            //   83bd94fdffff00       | cmp                 dword ptr [ebp - 0x26c], 0
            //   7505                 | jne                 7
            //   e9????????           |                     

        $sequence_2 = { 50 8d8de0fdffff 51 ff15???????? 6a00 6a20 8d9568f5ffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8de0fdffff         | lea                 ecx, [ebp - 0x220]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a20                 | push                0x20
            //   8d9568f5ffff         | lea                 edx, [ebp - 0xa98]

        $sequence_3 = { 50 8d45f0 64a300000000 8b4574 8945e0 8bb584000000 c745e4ffffffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b4574               | mov                 eax, dword ptr [ebp + 0x74]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8bb584000000         | mov                 esi, dword ptr [ebp + 0x84]
            //   c745e4ffffffff       | mov                 dword ptr [ebp - 0x1c], 0xffffffff

        $sequence_4 = { 33db 895de4 895dfc 53 6880000000 6a03 53 }
            // n = 7, score = 100
            //   33db                 | xor                 ebx, ebx
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   53                   | push                ebx
            //   6880000000           | push                0x80
            //   6a03                 | push                3
            //   53                   | push                ebx

        $sequence_5 = { c785bcfcffff00000000 83bdb8fcffff00 7e5c 6a00 8d85c0fcffff 50 }
            // n = 6, score = 100
            //   c785bcfcffff00000000     | mov    dword ptr [ebp - 0x344], 0
            //   83bdb8fcffff00       | cmp                 dword ptr [ebp - 0x348], 0
            //   7e5c                 | jle                 0x5e
            //   6a00                 | push                0
            //   8d85c0fcffff         | lea                 eax, [ebp - 0x340]
            //   50                   | push                eax

        $sequence_6 = { 899f4c030000 8d4748 8d559c 52 50 e8???????? 83c408 }
            // n = 7, score = 100
            //   899f4c030000         | mov                 dword ptr [edi + 0x34c], ebx
            //   8d4748               | lea                 eax, [edi + 0x48]
            //   8d559c               | lea                 edx, [ebp - 0x64]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_7 = { 8d9424fcd70000 52 8d442448 50 8d8c240c0f0000 51 8d9424240a0000 }
            // n = 7, score = 100
            //   8d9424fcd70000       | lea                 edx, [esp + 0xd7fc]
            //   52                   | push                edx
            //   8d442448             | lea                 eax, [esp + 0x48]
            //   50                   | push                eax
            //   8d8c240c0f0000       | lea                 ecx, [esp + 0xf0c]
            //   51                   | push                ecx
            //   8d9424240a0000       | lea                 edx, [esp + 0xa24]

        $sequence_8 = { 3145f8 33c5 50 8d45f0 64a300000000 33db 895dcc }
            // n = 7, score = 100
            //   3145f8               | xor                 dword ptr [ebp - 8], eax
            //   33c5                 | xor                 eax, ebp
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   33db                 | xor                 ebx, ebx
            //   895dcc               | mov                 dword ptr [ebp - 0x34], ebx

        $sequence_9 = { 8d8d0c020000 51 ffd7 3bf0 0f8e9a010000 }
            // n = 5, score = 100
            //   8d8d0c020000         | lea                 ecx, [ebp + 0x20c]
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   3bf0                 | cmp                 esi, eax
            //   0f8e9a010000         | jle                 0x1a0

    condition:
        7 of them and filesize < 319488
}