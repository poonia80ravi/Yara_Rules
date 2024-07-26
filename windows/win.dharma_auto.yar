rule win_dharma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.dharma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dharma"
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
        $sequence_0 = { 8b45f0 50 8b4dfc 2b4df0 d1f9 51 8b55fc }
            // n = 7, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   2b4df0               | sub                 ecx, dword ptr [ebp - 0x10]
            //   d1f9                 | sar                 ecx, 1
            //   51                   | push                ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_1 = { 8b5508 52 e8???????? 68f4010000 6a00 8d85e8fdffff 50 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   68f4010000           | push                0x1f4
            //   6a00                 | push                0
            //   8d85e8fdffff         | lea                 eax, [ebp - 0x218]
            //   50                   | push                eax

        $sequence_2 = { 6689044a 8b4d08 8b5104 83c201 8955ec 8b4508 8b4dec }
            // n = 7, score = 100
            //   6689044a             | mov                 word ptr [edx + ecx*2], ax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   83c201               | add                 edx, 1
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_3 = { c1f804 8b4d08 8b510c 668b0442 668945f8 8b4d0c }
            // n = 6, score = 100
            //   c1f804               | sar                 eax, 4
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]
            //   668b0442             | mov                 ax, word ptr [edx + eax*2]
            //   668945f8             | mov                 word ptr [ebp - 8], ax
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_4 = { ebd1 eb50 8b4d08 0fb7511c }
            // n = 4, score = 100
            //   ebd1                 | jmp                 0xffffffd3
            //   eb50                 | jmp                 0x52
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   0fb7511c             | movzx               edx, word ptr [ecx + 0x1c]

        $sequence_5 = { 8945fc 8b45fc 25ffff0000 0fb7c8 81e1ff000000 0fb6d1 8955fc }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   25ffff0000           | and                 eax, 0xffff
            //   0fb7c8               | movzx               ecx, ax
            //   81e1ff000000         | and                 ecx, 0xff
            //   0fb6d1               | movzx               edx, cl
            //   8955fc               | mov                 dword ptr [ebp - 4], edx

        $sequence_6 = { 50 8d8ddcfeffff 51 e8???????? 83c408 6a14 8d95dcfeffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8ddcfeffff         | lea                 ecx, [ebp - 0x124]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6a14                 | push                0x14
            //   8d95dcfeffff         | lea                 edx, [ebp - 0x124]

        $sequence_7 = { 51 8b55fc 52 e8???????? 83c40c 8b4518 50 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   50                   | push                eax

        $sequence_8 = { 335130 8b45f4 895034 8b4df4 8b55f4 8b4118 334234 }
            // n = 7, score = 100
            //   335130               | xor                 edx, dword ptr [ecx + 0x30]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   895034               | mov                 dword ptr [eax + 0x34], edx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b4118               | mov                 eax, dword ptr [ecx + 0x18]
            //   334234               | xor                 eax, dword ptr [edx + 0x34]

        $sequence_9 = { 0f84a7000000 8b45f4 50 ff15???????? 8945fc 837dfc00 }
            // n = 6, score = 100
            //   0f84a7000000         | je                  0xad
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0

    condition:
        7 of them and filesize < 204800
}