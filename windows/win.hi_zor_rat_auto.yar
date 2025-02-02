rule win_hi_zor_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hi_zor_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hi_zor_rat"
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
        $sequence_0 = { c7458c00003300 c7459024002500 c745943f003900 c7459838000a00 c7459c04002300 }
            // n = 5, score = 200
            //   c7458c00003300       | mov                 dword ptr [ebp - 0x74], 0x330000
            //   c7459024002500       | mov                 dword ptr [ebp - 0x70], 0x250024
            //   c745943f003900       | mov                 dword ptr [ebp - 0x6c], 0x39003f
            //   c7459838000a00       | mov                 dword ptr [ebp - 0x68], 0xa0038
            //   c7459c04002300       | mov                 dword ptr [ebp - 0x64], 0x230004

        $sequence_1 = { c1eb10 0bf3 8bd8 2500ff0000 }
            // n = 4, score = 200
            //   c1eb10               | shr                 ebx, 0x10
            //   0bf3                 | or                  esi, ebx
            //   8bd8                 | mov                 ebx, eax
            //   2500ff0000           | and                 eax, 0xff00

        $sequence_2 = { 895df8 895810 23df 0bde 035858 8975fc }
            // n = 6, score = 200
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   895810               | mov                 dword ptr [eax + 0x10], ebx
            //   23df                 | and                 ebx, edi
            //   0bde                 | or                  ebx, esi
            //   035858               | add                 ebx, dword ptr [eax + 0x58]
            //   8975fc               | mov                 dword ptr [ebp - 4], esi

        $sequence_3 = { ff15???????? 8bd8 6a01 b96f010000 8db5d8f8ffff }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   6a01                 | push                1
            //   b96f010000           | mov                 ecx, 0x16f
            //   8db5d8f8ffff         | lea                 esi, [ebp - 0x728]

        $sequence_4 = { 8b5d08 83c424 893e eb3d 8b45fc 40 8945fc }
            // n = 7, score = 200
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   83c424               | add                 esp, 0x24
            //   893e                 | mov                 dword ptr [esi], edi
            //   eb3d                 | jmp                 0x3f
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   40                   | inc                 eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_5 = { ffd6 8b8350010000 83c404 6a00 6880000000 6a02 6a00 }
            // n = 7, score = 200
            //   ffd6                 | call                esi
            //   8b8350010000         | mov                 eax, dword ptr [ebx + 0x150]
            //   83c404               | add                 esp, 4
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a02                 | push                2
            //   6a00                 | push                0

        $sequence_6 = { 8bd8 ff15???????? 83c404 85db 7505 8d7b05 eb1b }
            // n = 7, score = 200
            //   8bd8                 | mov                 ebx, eax
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   85db                 | test                ebx, ebx
            //   7505                 | jne                 7
            //   8d7b05               | lea                 edi, [ebx + 5]
            //   eb1b                 | jmp                 0x1d

        $sequence_7 = { 037814 8b5818 8bf3 f7d6 237014 }
            // n = 5, score = 200
            //   037814               | add                 edi, dword ptr [eax + 0x14]
            //   8b5818               | mov                 ebx, dword ptr [eax + 0x18]
            //   8bf3                 | mov                 esi, ebx
            //   f7d6                 | not                 esi
            //   237014               | and                 esi, dword ptr [eax + 0x14]

        $sequence_8 = { 6683b44568ffffff0d 40 83f844 7cf1 84c9 7437 8b8560ffffff }
            // n = 7, score = 200
            //   6683b44568ffffff0d     | xor    word ptr [ebp + eax*2 - 0x98], 0xd
            //   40                   | inc                 eax
            //   83f844               | cmp                 eax, 0x44
            //   7cf1                 | jl                  0xfffffff3
            //   84c9                 | test                cl, cl
            //   7437                 | je                  0x39
            //   8b8560ffffff         | mov                 eax, dword ptr [ebp - 0xa0]

        $sequence_9 = { 66833e00 0f85cffeffff 8b4d08 8d55f4 52 8d8594f3ffff 50 }
            // n = 7, score = 200
            //   66833e00             | cmp                 word ptr [esi], 0
            //   0f85cffeffff         | jne                 0xfffffed5
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   52                   | push                edx
            //   8d8594f3ffff         | lea                 eax, [ebp - 0xc6c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 73728
}