rule win_madmax_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.madmax."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.madmax"
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
        $sequence_0 = { e067 4a 59 39906f341ab7 3ca0 bc852f8958 aa }
            // n = 7, score = 100
            //   e067                 | loopne              0x69
            //   4a                   | dec                 edx
            //   59                   | pop                 ecx
            //   39906f341ab7         | cmp                 dword ptr [eax - 0x48e5cb91], edx
            //   3ca0                 | cmp                 al, 0xa0
            //   bc852f8958           | mov                 esp, 0x58892f85
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_1 = { fa 017689 ddea 1469 dc706e 4e 3da61f841d }
            // n = 7, score = 100
            //   fa                   | cli                 
            //   017689               | add                 dword ptr [esi - 0x77], esi
            //   ddea                 | fucomp              st(2)
            //   1469                 | adc                 al, 0x69
            //   dc706e               | fdiv                qword ptr [eax + 0x6e]
            //   4e                   | dec                 esi
            //   3da61f841d           | cmp                 eax, 0x1d841fa6

        $sequence_2 = { c686c800000043 c6864b01000043 c7466850101710 6a0d e8???????? 59 8365fc00 }
            // n = 7, score = 100
            //   c686c800000043       | mov                 byte ptr [esi + 0xc8], 0x43
            //   c6864b01000043       | mov                 byte ptr [esi + 0x14b], 0x43
            //   c7466850101710       | mov                 dword ptr [esi + 0x68], 0x10171050
            //   6a0d                 | push                0xd
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

        $sequence_3 = { b48b 37 a7 baabbc3c01 ad ef b57d }
            // n = 7, score = 100
            //   b48b                 | mov                 ah, 0x8b
            //   37                   | aaa                 
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]
            //   baabbc3c01           | mov                 edx, 0x13cbcab
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   ef                   | out                 dx, eax
            //   b57d                 | mov                 ch, 0x7d

        $sequence_4 = { c8785d3f 48 04e6 f9 37 301a d6 }
            // n = 7, score = 100
            //   c8785d3f             | enter               0x5d78, 0x3f
            //   48                   | dec                 eax
            //   04e6                 | add                 al, 0xe6
            //   f9                   | stc                 
            //   37                   | aaa                 
            //   301a                 | xor                 byte ptr [edx], bl
            //   d6                   | salc                

        $sequence_5 = { e71b 9f 08487e 188e1c9ba660 86b688ac3af3 2903 27 }
            // n = 7, score = 100
            //   e71b                 | out                 0x1b, eax
            //   9f                   | lahf                
            //   08487e               | or                  byte ptr [eax + 0x7e], cl
            //   188e1c9ba660         | sbb                 byte ptr [esi + 0x60a69b1c], cl
            //   86b688ac3af3         | xchg                byte ptr [esi - 0xcc55378], dh
            //   2903                 | sub                 dword ptr [ebx], eax
            //   27                   | daa                 

        $sequence_6 = { e8???????? 83c40c 8d4618 50 8bce e8???????? 895d0c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4618               | lea                 eax, [esi + 0x18]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   895d0c               | mov                 dword ptr [ebp + 0xc], ebx

        $sequence_7 = { dce6 1e 8a2d???????? f5 8c01 82d73b 8d1b }
            // n = 7, score = 100
            //   dce6                 | fsubr               st(6), st(0)
            //   1e                   | push                ds
            //   8a2d????????         |                     
            //   f5                   | cmc                 
            //   8c01                 | mov                 word ptr [ecx], es
            //   82d73b               | adc                 bh, 0x3b
            //   8d1b                 | lea                 ebx, [ebx]

        $sequence_8 = { de8166925cfc f6035e d0c1 b8d14e5201 3dd9dd2e7f bbd08c4bf8 48 }
            // n = 7, score = 100
            //   de8166925cfc         | fiadd               word ptr [ecx - 0x3a36d9a]
            //   f6035e               | test                byte ptr [ebx], 0x5e
            //   d0c1                 | rol                 cl, 1
            //   b8d14e5201           | mov                 eax, 0x1524ed1
            //   3dd9dd2e7f           | cmp                 eax, 0x7f2eddd9
            //   bbd08c4bf8           | mov                 ebx, 0xf84b8cd0
            //   48                   | dec                 eax

        $sequence_9 = { f600a7 45 209255d20ce6 47 40 bb5f547d28 95 }
            // n = 7, score = 100
            //   f600a7               | test                byte ptr [eax], 0xa7
            //   45                   | inc                 ebp
            //   209255d20ce6         | and                 byte ptr [edx - 0x19f32dab], dl
            //   47                   | inc                 edi
            //   40                   | inc                 eax
            //   bb5f547d28           | mov                 ebx, 0x287d545f
            //   95                   | xchg                eax, ebp

    condition:
        7 of them and filesize < 3227648
}