rule win_usbferry_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.usbferry."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.usbferry"
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
        $sequence_0 = { 56 57 c645ec66 c645ed6c c645ee61 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   c645ec66             | mov                 byte ptr [ebp - 0x14], 0x66
            //   c645ed6c             | mov                 byte ptr [ebp - 0x13], 0x6c
            //   c645ee61             | mov                 byte ptr [ebp - 0x12], 0x61

        $sequence_1 = { 8b95f8fffeff 52 8b4508 50 }
            // n = 4, score = 200
            //   8b95f8fffeff         | mov                 edx, dword ptr [ebp - 0x10008]
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax

        $sequence_2 = { 6a03 83fb08 ba???????? 58 0f4dc1 8bce }
            // n = 6, score = 200
            //   6a03                 | push                3
            //   83fb08               | cmp                 ebx, 8
            //   ba????????           |                     
            //   58                   | pop                 eax
            //   0f4dc1               | cmovge              eax, ecx
            //   8bce                 | mov                 ecx, esi

        $sequence_3 = { 83e801 0f84a8000000 83e811 7465 83e809 7475 }
            // n = 6, score = 200
            //   83e801               | sub                 eax, 1
            //   0f84a8000000         | je                  0xae
            //   83e811               | sub                 eax, 0x11
            //   7465                 | je                  0x67
            //   83e809               | sub                 eax, 9
            //   7475                 | je                  0x77

        $sequence_4 = { 8b9590f5ffff 8a4201 8885a0f5ffff 838590f5ffff01 }
            // n = 4, score = 200
            //   8b9590f5ffff         | mov                 edx, dword ptr [ebp - 0xa70]
            //   8a4201               | mov                 al, byte ptr [edx + 1]
            //   8885a0f5ffff         | mov                 byte ptr [ebp - 0xa60], al
            //   838590f5ffff01       | add                 dword ptr [ebp - 0xa70], 1

        $sequence_5 = { 754d 8bf3 8975d8 6a01 }
            // n = 4, score = 200
            //   754d                 | jne                 0x4f
            //   8bf3                 | mov                 esi, ebx
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   6a01                 | push                1

        $sequence_6 = { 75a5 8b4dfc 8b45f8 8b5718 2bd0 84db }
            // n = 6, score = 200
            //   75a5                 | jne                 0xffffffa7
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b5718               | mov                 edx, dword ptr [edi + 0x18]
            //   2bd0                 | sub                 edx, eax
            //   84db                 | test                bl, bl

        $sequence_7 = { ff15???????? 56 ff15???????? 8d8d74ecffff }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d8d74ecffff         | lea                 ecx, [ebp - 0x138c]

        $sequence_8 = { 66c745f87000 c78538ffffff55465665 c6853cffffff72 e8???????? 8d85b8feffff 50 8d8538ffffff }
            // n = 7, score = 200
            //   66c745f87000         | mov                 word ptr [ebp - 8], 0x70
            //   c78538ffffff55465665     | mov    dword ptr [ebp - 0xc8], 0x65564655
            //   c6853cffffff72       | mov                 byte ptr [ebp - 0xc4], 0x72
            //   e8????????           |                     
            //   8d85b8feffff         | lea                 eax, [ebp - 0x148]
            //   50                   | push                eax
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]

        $sequence_9 = { c785b0f7ffff44000000 c785dcf7ffff01000000 33d2 8995a0f7ffff }
            // n = 4, score = 200
            //   c785b0f7ffff44000000     | mov    dword ptr [ebp - 0x850], 0x44
            //   c785dcf7ffff01000000     | mov    dword ptr [ebp - 0x824], 1
            //   33d2                 | xor                 edx, edx
            //   8995a0f7ffff         | mov                 dword ptr [ebp - 0x860], edx

        $sequence_10 = { 51 e8???????? 83c40c c785b0f7ffff44000000 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c785b0f7ffff44000000     | mov    dword ptr [ebp - 0x850], 0x44

        $sequence_11 = { 8d8da8feffff 51 ff15???????? c685a4f9ffff00 6803010000 }
            // n = 5, score = 200
            //   8d8da8feffff         | lea                 ecx, [ebp - 0x158]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   c685a4f9ffff00       | mov                 byte ptr [ebp - 0x65c], 0
            //   6803010000           | push                0x103

        $sequence_12 = { c645d372 c645d473 c645d569 c645d66f c645d76e c645d85c c645d957 }
            // n = 7, score = 200
            //   c645d372             | mov                 byte ptr [ebp - 0x2d], 0x72
            //   c645d473             | mov                 byte ptr [ebp - 0x2c], 0x73
            //   c645d569             | mov                 byte ptr [ebp - 0x2b], 0x69
            //   c645d66f             | mov                 byte ptr [ebp - 0x2a], 0x6f
            //   c645d76e             | mov                 byte ptr [ebp - 0x29], 0x6e
            //   c645d85c             | mov                 byte ptr [ebp - 0x28], 0x5c
            //   c645d957             | mov                 byte ptr [ebp - 0x27], 0x57

        $sequence_13 = { 8b45e0 50 ff15???????? c745cc00000000 6afe 8d4df0 }
            // n = 6, score = 200
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0
            //   6afe                 | push                -2
            //   8d4df0               | lea                 ecx, [ebp - 0x10]

        $sequence_14 = { 8bd6 8d8de0faffff e8???????? 85c0 0f849b000000 83bda4faffff00 }
            // n = 6, score = 200
            //   8bd6                 | mov                 edx, esi
            //   8d8de0faffff         | lea                 ecx, [ebp - 0x520]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f849b000000         | je                  0xa1
            //   83bda4faffff00       | cmp                 dword ptr [ebp - 0x55c], 0

        $sequence_15 = { 03c2 8d53ff 50 8d0431 }
            // n = 4, score = 200
            //   03c2                 | add                 eax, edx
            //   8d53ff               | lea                 edx, [ebx - 1]
            //   50                   | push                eax
            //   8d0431               | lea                 eax, [ecx + esi]

    condition:
        7 of them and filesize < 638976
}