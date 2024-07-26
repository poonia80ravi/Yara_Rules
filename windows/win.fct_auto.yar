rule win_fct_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.fct."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fct"
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
        $sequence_0 = { 83f801 7221 83fe08 8d45d8 8d4a01 bb5c000000 }
            // n = 6, score = 100
            //   83f801               | cmp                 eax, 1
            //   7221                 | jb                  0x23
            //   83fe08               | cmp                 esi, 8
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   8d4a01               | lea                 ecx, [edx + 1]
            //   bb5c000000           | mov                 ebx, 0x5c

        $sequence_1 = { 6a01 e8???????? 8d8d80fdffff 8d5102 668b01 }
            // n = 5, score = 100
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8d8d80fdffff         | lea                 ecx, [ebp - 0x280]
            //   8d5102               | lea                 edx, [ecx + 2]
            //   668b01               | mov                 ax, word ptr [ecx]

        $sequence_2 = { 8bf9 89bd0cfdffff 33c0 8d5102 }
            // n = 4, score = 100
            //   8bf9                 | mov                 edi, ecx
            //   89bd0cfdffff         | mov                 dword ptr [ebp - 0x2f4], edi
            //   33c0                 | xor                 eax, eax
            //   8d5102               | lea                 edx, [ecx + 2]

        $sequence_3 = { 57 895594 894db0 8b048d50614100 8975b4 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   895594               | mov                 dword ptr [ebp - 0x6c], edx
            //   894db0               | mov                 dword ptr [ebp - 0x50], ecx
            //   8b048d50614100       | mov                 eax, dword ptr [ecx*4 + 0x416150]
            //   8975b4               | mov                 dword ptr [ebp - 0x4c], esi

        $sequence_4 = { 53 56 8b048550614100 8b7508 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b048550614100       | mov                 eax, dword ptr [eax*4 + 0x416150]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_5 = { 50 a1???????? 2bc6 56 03c2 50 57 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   a1????????           |                     
            //   2bc6                 | sub                 eax, esi
            //   56                   | push                esi
            //   03c2                 | add                 eax, edx
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_6 = { 6bc938 8b048550614100 0fb6440828 83e040 5d c3 }
            // n = 6, score = 100
            //   6bc938               | imul                ecx, ecx, 0x38
            //   8b048550614100       | mov                 eax, dword ptr [eax*4 + 0x416150]
            //   0fb6440828           | movzx               eax, byte ptr [eax + ecx + 0x28]
            //   83e040               | and                 eax, 0x40
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_7 = { e8???????? 8d8d80fdffff 8d5102 668b01 83c102 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d8d80fdffff         | lea                 ecx, [ebp - 0x280]
            //   8d5102               | lea                 edx, [ecx + 2]
            //   668b01               | mov                 ax, word ptr [ecx]
            //   83c102               | add                 ecx, 2

        $sequence_8 = { 8bec 8b4d08 33c0 3b0cc5e0fd4000 7427 40 83f82d }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   3b0cc5e0fd4000       | cmp                 ecx, dword ptr [eax*8 + 0x40fde0]
            //   7427                 | je                  0x29
            //   40                   | inc                 eax
            //   83f82d               | cmp                 eax, 0x2d

        $sequence_9 = { 6bf638 8b0c8d50614100 80643128fd 5f }
            // n = 4, score = 100
            //   6bf638               | imul                esi, esi, 0x38
            //   8b0c8d50614100       | mov                 ecx, dword ptr [ecx*4 + 0x416150]
            //   80643128fd           | and                 byte ptr [ecx + esi + 0x28], 0xfd
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 204800
}