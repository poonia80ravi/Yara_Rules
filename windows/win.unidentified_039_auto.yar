rule win_unidentified_039_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_039."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_039"
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
        $sequence_0 = { 885dd7 895d80 e8???????? c745e4a8610000 c745ece2320000 c745f09d440000 }
            // n = 6, score = 100
            //   885dd7               | mov                 byte ptr [ebp - 0x29], bl
            //   895d80               | mov                 dword ptr [ebp - 0x80], ebx
            //   e8????????           |                     
            //   c745e4a8610000       | mov                 dword ptr [ebp - 0x1c], 0x61a8
            //   c745ece2320000       | mov                 dword ptr [ebp - 0x14], 0x32e2
            //   c745f09d440000       | mov                 dword ptr [ebp - 0x10], 0x449d

        $sequence_1 = { 894538 8b452c 8b4d34 3bc8 7d0c ff7534 ff15???????? }
            // n = 7, score = 100
            //   894538               | mov                 dword ptr [ebp + 0x38], eax
            //   8b452c               | mov                 eax, dword ptr [ebp + 0x2c]
            //   8b4d34               | mov                 ecx, dword ptr [ebp + 0x34]
            //   3bc8                 | cmp                 ecx, eax
            //   7d0c                 | jge                 0xe
            //   ff7534               | push                dword ptr [ebp + 0x34]
            //   ff15????????         |                     

        $sequence_2 = { c745d8b65a0000 8b45f4 8b4df0 2bc8 034dd0 034dd4 8b45d8 }
            // n = 7, score = 100
            //   c745d8b65a0000       | mov                 dword ptr [ebp - 0x28], 0x5ab6
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   2bc8                 | sub                 ecx, eax
            //   034dd0               | add                 ecx, dword ptr [ebp - 0x30]
            //   034dd4               | add                 ecx, dword ptr [ebp - 0x2c]
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_3 = { ff15???????? c3 6a08 e8???????? 59 c3 33c0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   6a08                 | push                8
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 8b4dd8 0bc1 0dc8150000 8945d4 }
            // n = 4, score = 100
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   0bc1                 | or                  eax, ecx
            //   0dc8150000           | or                  eax, 0x15c8
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax

        $sequence_5 = { 8b4de8 0551750000 23c1 8b4dec 23c1 8945f0 8b45e8 }
            // n = 7, score = 100
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   0551750000           | add                 eax, 0x7551
            //   23c1                 | and                 eax, ecx
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   23c1                 | and                 eax, ecx
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_6 = { 2bd1 33c2 8945f4 8b4508 8b4d14 3bc8 7d09 }
            // n = 7, score = 100
            //   2bd1                 | sub                 edx, ecx
            //   33c2                 | xor                 eax, edx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   3bc8                 | cmp                 ecx, eax
            //   7d09                 | jge                 0xb

        $sequence_7 = { 50 c745fc01000000 e8???????? 8d4dc4 c645fc00 e8???????? c745e845320000 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   e8????????           |                     
            //   c745e845320000       | mov                 dword ptr [ebp - 0x18], 0x3245

        $sequence_8 = { 8945a4 66c74475a66e00 c7459cf1300000 c7459c4d710000 8b459c 2d540f0000 }
            // n = 6, score = 100
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax
            //   66c74475a66e00       | mov                 word ptr [ebp + esi*2 - 0x5a], 0x6e
            //   c7459cf1300000       | mov                 dword ptr [ebp - 0x64], 0x30f1
            //   c7459c4d710000       | mov                 dword ptr [ebp - 0x64], 0x714d
            //   8b459c               | mov                 eax, dword ptr [ebp - 0x64]
            //   2d540f0000           | sub                 eax, 0xf54

        $sequence_9 = { 23c8 8b45e4 33c8 894dcc 8b45e8 8b4de4 }
            // n = 6, score = 100
            //   23c8                 | and                 ecx, eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   33c8                 | xor                 ecx, eax
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

    condition:
        7 of them and filesize < 262144
}