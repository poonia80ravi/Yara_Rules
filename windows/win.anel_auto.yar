rule win_anel_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.anel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anel"
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
        $sequence_0 = { 33c0 c7431407000000 894b10 668903 c745e801000000 394d18 746b }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   c7431407000000       | mov                 dword ptr [ebx + 0x14], 7
            //   894b10               | mov                 dword ptr [ebx + 0x10], ecx
            //   668903               | mov                 word ptr [ebx], ax
            //   c745e801000000       | mov                 dword ptr [ebp - 0x18], 1
            //   394d18               | cmp                 dword ptr [ebp + 0x18], ecx
            //   746b                 | je                  0x6d

        $sequence_1 = { 57 3bf0 731b 8b0b 3bce 7715 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   3bf0                 | cmp                 esi, eax
            //   731b                 | jae                 0x1d
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   3bce                 | cmp                 ecx, esi
            //   7715                 | ja                  0x17

        $sequence_2 = { ff15???????? 6a01 33ff 8d75b4 898524ffffff e8???????? 6a01 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   33ff                 | xor                 edi, edi
            //   8d75b4               | lea                 esi, [ebp - 0x4c]
            //   898524ffffff         | mov                 dword ptr [ebp - 0xdc], eax
            //   e8????????           |                     
            //   6a01                 | push                1

        $sequence_3 = { ff742420 ff74241c e8???????? 59 89442418 59 6a01 }
            // n = 7, score = 200
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   59                   | pop                 ecx
            //   6a01                 | push                1

        $sequence_4 = { 899d24efffff 899d28efffff 899d20efffff 395f10 743e 68???????? 8d4598 }
            // n = 7, score = 200
            //   899d24efffff         | mov                 dword ptr [ebp - 0x10dc], ebx
            //   899d28efffff         | mov                 dword ptr [ebp - 0x10d8], ebx
            //   899d20efffff         | mov                 dword ptr [ebp - 0x10e0], ebx
            //   395f10               | cmp                 dword ptr [edi + 0x10], ebx
            //   743e                 | je                  0x40
            //   68????????           |                     
            //   8d4598               | lea                 eax, [ebp - 0x68]

        $sequence_5 = { 56 57 8b39 2bc7 be94000000 99 8bde }
            // n = 7, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b39                 | mov                 edi, dword ptr [ecx]
            //   2bc7                 | sub                 eax, edi
            //   be94000000           | mov                 esi, 0x94
            //   99                   | cdq                 
            //   8bde                 | mov                 ebx, esi

        $sequence_6 = { a5 a5 838548feffff10 8b8548feffff 2b8544feffff 83a58cfeffff00 c1f804 }
            // n = 7, score = 200
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   838548feffff10       | add                 dword ptr [ebp - 0x1b8], 0x10
            //   8b8548feffff         | mov                 eax, dword ptr [ebp - 0x1b8]
            //   2b8544feffff         | sub                 eax, dword ptr [ebp - 0x1bc]
            //   83a58cfeffff00       | and                 dword ptr [ebp - 0x174], 0
            //   c1f804               | sar                 eax, 4

        $sequence_7 = { e8???????? 83ec1c 8bf4 89a558feffff 68???????? c645fc03 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   8bf4                 | mov                 esi, esp
            //   89a558feffff         | mov                 dword ptr [ebp - 0x1a8], esp
            //   68????????           |                     
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3

        $sequence_8 = { 6a01 83c61c 33ff e8???????? 8b75fc 6a01 e8???????? }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   83c61c               | add                 esi, 0x1c
            //   33ff                 | xor                 edi, edi
            //   e8????????           |                     
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   6a01                 | push                1
            //   e8????????           |                     

        $sequence_9 = { 50 e8???????? 59 8945e8 85c0 0f848e000000 8365fc00 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   85c0                 | test                eax, eax
            //   0f848e000000         | je                  0x94
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

    condition:
        7 of them and filesize < 376832
}