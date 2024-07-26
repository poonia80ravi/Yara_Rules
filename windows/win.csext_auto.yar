rule win_csext_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-05-30"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.4.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.csext"
        malpedia_rule_date = "20200529"
        malpedia_hash = "92c362319514e5a6da26204961446caa3a8b32a8"
        malpedia_version = "20200529"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using yara-signator.
     * The code and documentation / approach is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { ff11 83c418 8bc7 5f 5e c9 c3 }
            // n = 7, score = 200
            //   ff11                 | call                dword ptr [ecx]
            //   83c418               | add                 esp, 0x18
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_1 = { eb37 ff7610 ff75fc e8???????? 59 59 6a02 }
            // n = 7, score = 200
            //   eb37                 | jmp                 0x39
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6a02                 | push                2

        $sequence_2 = { f7d3 0bdf 33de 035df4 897dfc 8b7818 03df }
            // n = 7, score = 200
            //   f7d3                 | not                 ebx
            //   0bdf                 | or                  ebx, edi
            //   33de                 | xor                 ebx, esi
            //   035df4               | add                 ebx, dword ptr [ebp - 0xc]
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   8b7818               | mov                 edi, dword ptr [eax + 0x18]
            //   03df                 | add                 ebx, edi

        $sequence_3 = { f7d9 034dc8 8975dc 03ca 8b55e0 894dd8 8b4de4 }
            // n = 7, score = 200
            //   f7d9                 | neg                 ecx
            //   034dc8               | add                 ecx, dword ptr [ebp - 0x38]
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   03ca                 | add                 ecx, edx
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_4 = { eb02 33db 83f903 895c8f04 895c8f14 7d04 895c8f24 }
            // n = 7, score = 200
            //   eb02                 | jmp                 4
            //   33db                 | xor                 ebx, ebx
            //   83f903               | cmp                 ecx, 3
            //   895c8f04             | mov                 dword ptr [edi + ecx*4 + 4], ebx
            //   895c8f14             | mov                 dword ptr [edi + ecx*4 + 0x14], ebx
            //   7d04                 | jge                 6
            //   895c8f24             | mov                 dword ptr [edi + ecx*4 + 0x24], ebx

        $sequence_5 = { 68???????? e9???????? ffb3e8000000 e8???????? ffb3e4000000 8bf0 83c605 }
            // n = 7, score = 200
            //   68????????           |                     
            //   e9????????           |                     
            //   ffb3e8000000         | push                dword ptr [ebx + 0xe8]
            //   e8????????           |                     
            //   ffb3e4000000         | push                dword ptr [ebx + 0xe4]
            //   8bf0                 | mov                 esi, eax
            //   83c605               | add                 esi, 5

        $sequence_6 = { ff742410 8b08 ff742410 50 ff5108 83c40c 894608 }
            // n = 7, score = 200
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   83c40c               | add                 esp, 0xc
            //   894608               | mov                 dword ptr [esi + 8], eax

        $sequence_7 = { 897d08 33c0 40 394508 7d03 894508 53 }
            // n = 7, score = 200
            //   897d08               | mov                 dword ptr [ebp + 8], edi
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   394508               | cmp                 dword ptr [ebp + 8], eax
            //   7d03                 | jge                 5
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   53                   | push                ebx

        $sequence_8 = { ff15???????? 85c0 7549 53 e8???????? ff7594 e8???????? }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7549                 | jne                 0x4b
            //   53                   | push                ebx
            //   e8????????           |                     
            //   ff7594               | push                dword ptr [ebp - 0x6c]
            //   e8????????           |                     

        $sequence_9 = { ffb0d4000000 e8???????? 83c410 5d c3 ff742408 e8???????? }
            // n = 7, score = 200
            //   ffb0d4000000         | push                dword ptr [eax + 0xd4]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 2711552
}