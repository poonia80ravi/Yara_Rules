rule win_regretlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.regretlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.regretlocker"
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
        $sequence_0 = { 33d2 59 899788000000 898f8c000000 885778 8d8790000000 895010 }
            // n = 7, score = 100
            //   33d2                 | xor                 edx, edx
            //   59                   | pop                 ecx
            //   899788000000         | mov                 dword ptr [edi + 0x88], edx
            //   898f8c000000         | mov                 dword ptr [edi + 0x8c], ecx
            //   885778               | mov                 byte ptr [edi + 0x78], dl
            //   8d8790000000         | lea                 eax, [edi + 0x90]
            //   895010               | mov                 dword ptr [eax + 0x10], edx

        $sequence_1 = { e8???????? 8b450c 8b00 89461c 8bc6 5e c9 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c9                   | leave               

        $sequence_2 = { 50 e8???????? c9 c3 56 8bf1 8b4610 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   c9                   | leave               
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]

        $sequence_3 = { 0f855bffffff 8b4df4 5f 5e 64890d00000000 c9 c3 }
            // n = 7, score = 100
            //   0f855bffffff         | jne                 0xffffff61
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_4 = { 8d8d14ffffff 50 e8???????? 8d85fcfeffff c645fc0c 50 8d8d14ffffff }
            // n = 7, score = 100
            //   8d8d14ffffff         | lea                 ecx, [ebp - 0xec]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   c645fc0c             | mov                 byte ptr [ebp - 4], 0xc
            //   50                   | push                eax
            //   8d8d14ffffff         | lea                 ecx, [ebp - 0xec]

        $sequence_5 = { 3b7dfc 76a3 8b7508 8d4dac 8d5101 83661000 c746140f000000 }
            // n = 7, score = 100
            //   3b7dfc               | cmp                 edi, dword ptr [ebp - 4]
            //   76a3                 | jbe                 0xffffffa5
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   8d5101               | lea                 edx, [ecx + 1]
            //   83661000             | and                 dword ptr [esi + 0x10], 0
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf

        $sequence_6 = { 75ca eb07 33ff eb03 83ceff 893b 807df400 }
            // n = 7, score = 100
            //   75ca                 | jne                 0xffffffcc
            //   eb07                 | jmp                 9
            //   33ff                 | xor                 edi, edi
            //   eb03                 | jmp                 5
            //   83ceff               | or                  esi, 0xffffffff
            //   893b                 | mov                 dword ptr [ebx], edi
            //   807df400             | cmp                 byte ptr [ebp - 0xc], 0

        $sequence_7 = { 0fb706 6a2f 5b 6a5c 5a 8955fc 663bc2 }
            // n = 7, score = 100
            //   0fb706               | movzx               eax, word ptr [esi]
            //   6a2f                 | push                0x2f
            //   5b                   | pop                 ebx
            //   6a5c                 | push                0x5c
            //   5a                   | pop                 edx
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   663bc2               | cmp                 ax, dx

        $sequence_8 = { c1f906 53 6bd830 56 8b048d58d74600 57 }
            // n = 6, score = 100
            //   c1f906               | sar                 ecx, 6
            //   53                   | push                ebx
            //   6bd830               | imul                ebx, eax, 0x30
            //   56                   | push                esi
            //   8b048d58d74600       | mov                 eax, dword ptr [ecx*4 + 0x46d758]
            //   57                   | push                edi

        $sequence_9 = { 894110 894114 e8???????? 8b4df4 8bc6 5e 64890d00000000 }
            // n = 7, score = 100
            //   894110               | mov                 dword ptr [ecx + 0x10], eax
            //   894114               | mov                 dword ptr [ecx + 0x14], eax
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

    condition:
        7 of them and filesize < 1021952
}