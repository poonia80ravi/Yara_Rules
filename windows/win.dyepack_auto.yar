rule win_dyepack_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.dyepack."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dyepack"
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
        $sequence_0 = { 7815 7f08 81f900100000 760b b900100000 895c2420 }
            // n = 6, score = 300
            //   7815                 | js                  0x17
            //   7f08                 | jg                  0xa
            //   81f900100000         | cmp                 ecx, 0x1000
            //   760b                 | jbe                 0xd
            //   b900100000           | mov                 ecx, 0x1000
            //   895c2420             | mov                 dword ptr [esp + 0x20], ebx

        $sequence_1 = { 895c2410 50 56 895c241c ff15???????? 53 }
            // n = 6, score = 300
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx
            //   50                   | push                eax
            //   56                   | push                esi
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx
            //   ff15????????         |                     
            //   53                   | push                ebx

        $sequence_2 = { 33ed 33ff 3bc3 7c60 7f0a }
            // n = 5, score = 300
            //   33ed                 | xor                 ebp, ebp
            //   33ff                 | xor                 edi, edi
            //   3bc3                 | cmp                 eax, ebx
            //   7c60                 | jl                  0x62
            //   7f0a                 | jg                  0xc

        $sequence_3 = { ff15???????? 56 ff15???????? 8d442410 895c2410 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx

        $sequence_4 = { ff15???????? 5f 5e 5b 81c414100000 c3 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c414100000         | add                 esp, 0x1014
            //   c3                   | ret                 

        $sequence_5 = { 33ff 3bc3 7c60 7f0a 3bcb }
            // n = 5, score = 300
            //   33ff                 | xor                 edi, edi
            //   3bc3                 | cmp                 eax, ebx
            //   7c60                 | jl                  0x62
            //   7f0a                 | jg                  0xc
            //   3bcb                 | cmp                 ecx, ebx

        $sequence_6 = { 56 ff15???????? 8b8c2428100000 53 51 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b8c2428100000       | mov                 ecx, dword ptr [esp + 0x1028]
            //   53                   | push                ebx
            //   51                   | push                ecx

        $sequence_7 = { 53 52 8d44242c 51 50 56 ff15???????? }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   52                   | push                edx
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_8 = { 50 56 895c241c ff15???????? 53 53 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   56                   | push                esi
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_9 = { 53 aa 8b842434100000 53 6800000040 }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8b842434100000       | mov                 eax, dword ptr [esp + 0x1034]
            //   53                   | push                ebx
            //   6800000040           | push                0x40000000

    condition:
        7 of them and filesize < 212992
}