rule win_ramnit_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ramnit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ramnit"
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
        $sequence_0 = { 8a07 3a4510 7407 b800000000 eb02 8bc7 }
            // n = 6, score = 4000
            //   8a07                 | mov                 al, byte ptr [edi]
            //   3a4510               | cmp                 al, byte ptr [ebp + 0x10]
            //   7407                 | je                  9
            //   b800000000           | mov                 eax, 0
            //   eb02                 | jmp                 4
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { ff750c ff7508 e8???????? 03450c 5a }
            // n = 5, score = 4000
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   03450c               | add                 eax, dword ptr [ebp + 0xc]
            //   5a                   | pop                 edx

        $sequence_2 = { ff75fc e8???????? 83f801 7417 8b5dfc 43 }
            // n = 6, score = 4000
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83f801               | cmp                 eax, 1
            //   7417                 | je                  0x19
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   43                   | inc                 ebx

        $sequence_3 = { 5f 59 5a 5b c9 c20800 55 }
            // n = 7, score = 4000
            //   5f                   | pop                 edi
            //   59                   | pop                 ecx
            //   5a                   | pop                 edx
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   55                   | push                ebp

        $sequence_4 = { f7d3 23c3 5a 59 5b }
            // n = 5, score = 4000
            //   f7d3                 | not                 ebx
            //   23c3                 | and                 eax, ebx
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   5b                   | pop                 ebx

        $sequence_5 = { 3c7a 7702 2c20 c9 c20400 }
            // n = 5, score = 4000
            //   3c7a                 | cmp                 al, 0x7a
            //   7702                 | ja                  4
            //   2c20                 | sub                 al, 0x20
            //   c9                   | leave               
            //   c20400               | ret                 4

        $sequence_6 = { 5f 59 5a 5b c9 c21000 }
            // n = 6, score = 4000
            //   5f                   | pop                 edi
            //   59                   | pop                 ecx
            //   5a                   | pop                 edx
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c21000               | ret                 0x10

        $sequence_7 = { 6a00 ff750c ff75fc ff7508 e8???????? 8b45fc 03450c }
            // n = 7, score = 4000
            //   6a00                 | push                0
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   03450c               | add                 eax, dword ptr [ebp + 0xc]

        $sequence_8 = { 57 56 fc 8b4d0c 8b7d08 b000 f3aa }
            // n = 7, score = 4000
            //   57                   | push                edi
            //   56                   | push                esi
            //   fc                   | cld                 
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   b000                 | mov                 al, 0
            //   f3aa                 | rep stosb           byte ptr es:[edi], al

        $sequence_9 = { 83e801 89450c 8b4514 83e801 894514 }
            // n = 5, score = 4000
            //   83e801               | sub                 eax, 1
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   83e801               | sub                 eax, 1
            //   894514               | mov                 dword ptr [ebp + 0x14], eax

    condition:
        7 of them and filesize < 470016
}