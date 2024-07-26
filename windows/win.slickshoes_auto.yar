rule win_slickshoes_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.slickshoes."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slickshoes"
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
        $sequence_0 = { fb 55 e9???????? 0504000000 870424 5c e9???????? }
            // n = 7, score = 100
            //   fb                   | sti                 
            //   55                   | push                ebp
            //   e9????????           |                     
            //   0504000000           | add                 eax, 4
            //   870424               | xchg                dword ptr [esp], eax
            //   5c                   | pop                 esp
            //   e9????????           |                     

        $sequence_1 = { ff3424 e9???????? f7d0 83e801 57 6841e9ff5b 5f }
            // n = 7, score = 100
            //   ff3424               | push                dword ptr [esp]
            //   e9????????           |                     
            //   f7d0                 | not                 eax
            //   83e801               | sub                 eax, 1
            //   57                   | push                edi
            //   6841e9ff5b           | push                0x5bffe941
            //   5f                   | pop                 edi

        $sequence_2 = { 89f8 09f6 8b12 81c600080000 8b09 0500080000 81cfffff0000 }
            // n = 7, score = 100
            //   89f8                 | mov                 eax, edi
            //   09f6                 | or                  esi, esi
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   81c600080000         | add                 esi, 0x800
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   0500080000           | add                 eax, 0x800
            //   81cfffff0000         | or                  edi, 0xffff

        $sequence_3 = { e69b ba2a2077f8 39c4 90 00dc 4c d6 }
            // n = 7, score = 100
            //   e69b                 | out                 0x9b, al
            //   ba2a2077f8           | mov                 edx, 0xf877202a
            //   39c4                 | cmp                 esp, eax
            //   90                   | nop                 
            //   00dc                 | add                 ah, bl
            //   4c                   | dec                 esp
            //   d6                   | salc                

        $sequence_4 = { f71424 5b 4b 81cb449feb67 81e38248e95f 56 bedaaaff7f }
            // n = 7, score = 100
            //   f71424               | not                 dword ptr [esp]
            //   5b                   | pop                 ebx
            //   4b                   | dec                 ebx
            //   81cb449feb67         | or                  ebx, 0x67eb9f44
            //   81e38248e95f         | and                 ebx, 0x5fe94882
            //   56                   | push                esi
            //   bedaaaff7f           | mov                 esi, 0x7fffaada

        $sequence_5 = { e9???????? 892c24 bd5238da3b f7d5 81e5d3652c52 56 be1254da6f }
            // n = 7, score = 100
            //   e9????????           |                     
            //   892c24               | mov                 dword ptr [esp], ebp
            //   bd5238da3b           | mov                 ebp, 0x3bda3852
            //   f7d5                 | not                 ebp
            //   81e5d3652c52         | and                 ebp, 0x522c65d3
            //   56                   | push                esi
            //   be1254da6f           | mov                 esi, 0x6fda5412

        $sequence_6 = { ff36 81e780000000 be00020000 9d 66d308 89e8 0504000000 }
            // n = 7, score = 100
            //   ff36                 | push                dword ptr [esi]
            //   81e780000000         | and                 edi, 0x80
            //   be00020000           | mov                 esi, 0x200
            //   9d                   | popfd               
            //   66d308               | ror                 word ptr [eax], cl
            //   89e8                 | mov                 eax, ebp
            //   0504000000           | add                 eax, 4

        $sequence_7 = { e9???????? 01c5 58 50 b89b72ff7b f7d0 40 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   01c5                 | add                 ebp, eax
            //   58                   | pop                 eax
            //   50                   | push                eax
            //   b89b72ff7b           | mov                 eax, 0x7bff729b
            //   f7d0                 | not                 eax
            //   40                   | inc                 eax

        $sequence_8 = { f7d2 e9???????? 89c8 59 f7d0 2dadccc72a 01c3 }
            // n = 7, score = 100
            //   f7d2                 | not                 edx
            //   e9????????           |                     
            //   89c8                 | mov                 eax, ecx
            //   59                   | pop                 ecx
            //   f7d0                 | not                 eax
            //   2dadccc72a           | sub                 eax, 0x2ac7ccad
            //   01c3                 | add                 ebx, eax

        $sequence_9 = { bf04000000 81ed11de5b0c e9???????? 57 682a82f717 e9???????? 83c404 }
            // n = 7, score = 100
            //   bf04000000           | mov                 edi, 4
            //   81ed11de5b0c         | sub                 ebp, 0xc5bde11
            //   e9????????           |                     
            //   57                   | push                edi
            //   682a82f717           | push                0x17f7822a
            //   e9????????           |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 11198464
}