rule win_megumin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.megumin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.megumin"
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
        $sequence_0 = { 8d8d90fcffff e8???????? 8b08 8b4904 }
            // n = 4, score = 200
            //   8d8d90fcffff         | lea                 ecx, [ebp - 0x370]
            //   e8????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]

        $sequence_1 = { 6a34 56 e8???????? 83c408 c745fc01000000 8b75d0 8b7dcc }
            // n = 7, score = 200
            //   6a34                 | push                0x34
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8b75d0               | mov                 esi, dword ptr [ebp - 0x30]
            //   8b7dcc               | mov                 edi, dword ptr [ebp - 0x34]

        $sequence_2 = { e8???????? 8bf8 83c40c 89bd0cffffff 83ffff 0f8401040000 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c40c               | add                 esp, 0xc
            //   89bd0cffffff         | mov                 dword ptr [ebp - 0xf4], edi
            //   83ffff               | cmp                 edi, -1
            //   0f8401040000         | je                  0x407

        $sequence_3 = { c745d000000000 50 6a00 6a00 6a00 6a00 6a00 }
            // n = 7, score = 200
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_4 = { 899594fdffff 837dcc10 8d45b8 52 0f4345b8 8d4dd4 837de810 }
            // n = 7, score = 200
            //   899594fdffff         | mov                 dword ptr [ebp - 0x26c], edx
            //   837dcc10             | cmp                 dword ptr [ebp - 0x34], 0x10
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   52                   | push                edx
            //   0f4345b8             | cmovae              eax, dword ptr [ebp - 0x48]
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   837de810             | cmp                 dword ptr [ebp - 0x18], 0x10

        $sequence_5 = { 755f 83ec1c 8d8550ffffff 8bcc 50 e8???????? 8d45c4 }
            // n = 7, score = 200
            //   755f                 | jne                 0x61
            //   83ec1c               | sub                 esp, 0x1c
            //   8d8550ffffff         | lea                 eax, [ebp - 0xb0]
            //   8bcc                 | mov                 ecx, esp
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45c4               | lea                 eax, [ebp - 0x3c]

        $sequence_6 = { 0f1f00 8a0a 42 3a0c07 7505 40 }
            // n = 6, score = 200
            //   0f1f00               | nop                 dword ptr [eax]
            //   8a0a                 | mov                 cl, byte ptr [edx]
            //   42                   | inc                 edx
            //   3a0c07               | cmp                 cl, byte ptr [edi + eax]
            //   7505                 | jne                 7
            //   40                   | inc                 eax

        $sequence_7 = { 6a00 50 e8???????? 83c404 8d45c0 8d8d00ffffff 50 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d45c0               | lea                 eax, [ebp - 0x40]
            //   8d8d00ffffff         | lea                 ecx, [ebp - 0x100]
            //   50                   | push                eax

        $sequence_8 = { 85c9 0f8455020000 83bde8fbffff10 8d85d4fbffff 6a01 0f4385d4fbffff }
            // n = 6, score = 200
            //   85c9                 | test                ecx, ecx
            //   0f8455020000         | je                  0x25b
            //   83bde8fbffff10       | cmp                 dword ptr [ebp - 0x418], 0x10
            //   8d85d4fbffff         | lea                 eax, [ebp - 0x42c]
            //   6a01                 | push                1
            //   0f4385d4fbffff       | cmovae              eax, dword ptr [ebp - 0x42c]

        $sequence_9 = { ff15???????? 668945c6 b802000000 668945c4 8b460c 6a10 8b00 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   668945c6             | mov                 word ptr [ebp - 0x3a], ax
            //   b802000000           | mov                 eax, 2
            //   668945c4             | mov                 word ptr [ebp - 0x3c], ax
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   6a10                 | push                0x10
            //   8b00                 | mov                 eax, dword ptr [eax]

    condition:
        7 of them and filesize < 1007616
}