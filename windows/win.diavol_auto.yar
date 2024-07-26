rule win_diavol_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.diavol."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diavol"
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
        $sequence_0 = { 68???????? 53 8bf8 e8???????? 83c41c 85c0 741c }
            // n = 7, score = 100
            //   68????????           |                     
            //   53                   | push                ebx
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   85c0                 | test                eax, eax
            //   741c                 | je                  0x1e

        $sequence_1 = { 56 e8???????? 83c404 03bd38c2ffff 83d300 3b9d34c2ffff }
            // n = 6, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   03bd38c2ffff         | add                 edi, dword ptr [ebp - 0x3dc8]
            //   83d300               | adc                 ebx, 0
            //   3b9d34c2ffff         | cmp                 ebx, dword ptr [ebp - 0x3dcc]

        $sequence_2 = { 53 ff15???????? ff15???????? b806000000 5f }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   b806000000           | mov                 eax, 6
            //   5f                   | pop                 edi

        $sequence_3 = { 8bf2 f3a5 8bc8 8d85f4efffff }
            // n = 4, score = 100
            //   8bf2                 | mov                 esi, edx
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   8d85f4efffff         | lea                 eax, [ebp - 0x100c]

        $sequence_4 = { 8d8d94f3ffff 51 56 ff15???????? 85c0 }
            // n = 5, score = 100
            //   8d8d94f3ffff         | lea                 ecx, [ebp - 0xc6c]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 6a00 8d45cc 50 6a2c 8d4dd0 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   6a2c                 | push                0x2c
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]

        $sequence_6 = { 8945f0 e8???????? 8b45f4 83c40c 6880000000 8d55f0 52 }
            // n = 7, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   83c40c               | add                 esp, 0xc
            //   6880000000           | push                0x80
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx

        $sequence_7 = { 56 ff15???????? 8b4dfc 8b85c4fbffff 33cd 5e e8???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b85c4fbffff         | mov                 eax, dword ptr [ebp - 0x43c]
            //   33cd                 | xor                 ecx, ebp
            //   5e                   | pop                 esi
            //   e8????????           |                     

        $sequence_8 = { 8bd0 52 8d45a0 50 68???????? 68???????? 8d95a0f9ffff }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   52                   | push                edx
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   50                   | push                eax
            //   68????????           |                     
            //   68????????           |                     
            //   8d95a0f9ffff         | lea                 edx, [ebp - 0x660]

        $sequence_9 = { 81ec20010000 a1???????? 33c5 8945fc 6880000000 8d8578ffffff }
            // n = 6, score = 100
            //   81ec20010000         | sub                 esp, 0x120
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   6880000000           | push                0x80
            //   8d8578ffffff         | lea                 eax, [ebp - 0x88]

    condition:
        7 of them and filesize < 191488
}