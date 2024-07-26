rule win_netkey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.netkey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netkey"
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
        $sequence_0 = { 880e 5f 5e 8b4dfc 33cd e8???????? 8be5 }
            // n = 7, score = 200
            //   880e                 | mov                 byte ptr [esi], cl
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp

        $sequence_1 = { 8b4d08 33c0 3b0cc5282f4300 7427 40 83f82d }
            // n = 6, score = 200
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   3b0cc5282f4300       | cmp                 ecx, dword ptr [eax*8 + 0x432f28]
            //   7427                 | je                  0x29
            //   40                   | inc                 eax
            //   83f82d               | cmp                 eax, 0x2d

        $sequence_2 = { 50 e8???????? 83c40c 6a03 ba53000000 8d8d68feffff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a03                 | push                3
            //   ba53000000           | mov                 edx, 0x53
            //   8d8d68feffff         | lea                 ecx, [ebp - 0x198]

        $sequence_3 = { 33c5 8945fc 56 57 e8???????? 6a00 6880000000 }
            // n = 7, score = 200
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6880000000           | push                0x80

        $sequence_4 = { 85ff 753f 8d45e0 c745dcb4f24200 50 8d45e8 c745e8d4b34300 }
            // n = 7, score = 200
            //   85ff                 | test                edi, edi
            //   753f                 | jne                 0x41
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   c745dcb4f24200       | mov                 dword ptr [ebp - 0x24], 0x42f2b4
            //   50                   | push                eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   c745e8d4b34300       | mov                 dword ptr [ebp - 0x18], 0x43b3d4

        $sequence_5 = { 56 ff15???????? 85c0 74d2 53 8b1d???????? 660f1f840000000000 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74d2                 | je                  0xffffffd4
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   660f1f840000000000     | nop    word ptr [eax + eax]

        $sequence_6 = { 8b460c 0555fcc002 3141e4 8b4610 05b0407c05 }
            // n = 5, score = 200
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   0555fcc002           | add                 eax, 0x2c0fc55
            //   3141e4               | xor                 dword ptr [ecx - 0x1c], eax
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]
            //   05b0407c05           | add                 eax, 0x57c40b0

        $sequence_7 = { 8bfa 2bf9 0f1f8000000000 0f100406 }
            // n = 4, score = 200
            //   8bfa                 | mov                 edi, edx
            //   2bf9                 | sub                 edi, ecx
            //   0f1f8000000000       | nop                 dword ptr [eax]
            //   0f100406             | movups              xmm0, xmmword ptr [esi + eax]

        $sequence_8 = { 83e13f c1f806 6bc930 f6451402 8b0485a8214400 c644082900 }
            // n = 6, score = 200
            //   83e13f               | and                 ecx, 0x3f
            //   c1f806               | sar                 eax, 6
            //   6bc930               | imul                ecx, ecx, 0x30
            //   f6451402             | test                byte ptr [ebp + 0x14], 2
            //   8b0485a8214400       | mov                 eax, dword ptr [eax*4 + 0x4421a8]
            //   c644082900           | mov                 byte ptr [eax + ecx + 0x29], 0

        $sequence_9 = { 56 e8???????? 83c430 803e00 7504 33c9 eb0f }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7504                 | jne                 6
            //   33c9                 | xor                 ecx, ecx
            //   eb0f                 | jmp                 0x11

    condition:
        7 of them and filesize < 606208
}