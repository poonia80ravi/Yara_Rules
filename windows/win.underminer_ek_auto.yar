rule win_underminer_ek_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.underminer_ek."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.underminer_ek"
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
        $sequence_0 = { 0303 50 e8???????? 837e1410 7205 8b36 8975fc }
            // n = 7, score = 100
            //   0303                 | add                 eax, dword ptr [ebx]
            //   50                   | push                eax
            //   e8????????           |                     
            //   837e1410             | cmp                 dword ptr [esi + 0x14], 0x10
            //   7205                 | jb                  7
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   8975fc               | mov                 dword ptr [ebp - 4], esi

        $sequence_1 = { 0305???????? 5f 03c1 0115???????? }
            // n = 4, score = 100
            //   0305????????         |                     
            //   5f                   | pop                 edi
            //   03c1                 | add                 eax, ecx
            //   0115????????         |                     

        $sequence_2 = { 7f03 83c120 3bd7 7304 3bc1 74d4 }
            // n = 6, score = 100
            //   7f03                 | jg                  5
            //   83c120               | add                 ecx, 0x20
            //   3bd7                 | cmp                 edx, edi
            //   7304                 | jae                 6
            //   3bc1                 | cmp                 eax, ecx
            //   74d4                 | je                  0xffffffd6

        $sequence_3 = { 384601 7409 03751c eb85 }
            // n = 4, score = 100
            //   384601               | cmp                 byte ptr [esi + 1], al
            //   7409                 | je                  0xb
            //   03751c               | add                 esi, dword ptr [ebp + 0x1c]
            //   eb85                 | jmp                 0xffffff87

        $sequence_4 = { 7630 83c710 8b07 3bc1 7618 }
            // n = 5, score = 100
            //   7630                 | jbe                 0x32
            //   83c710               | add                 edi, 0x10
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   3bc1                 | cmp                 eax, ecx
            //   7618                 | jbe                 0x1a

        $sequence_5 = { 85db 7425 8b5004 8b08 }
            // n = 4, score = 100
            //   85db                 | test                ebx, ebx
            //   7425                 | je                  0x27
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_6 = { 03048d582c4300 eb05 b8???????? f6402820 }
            // n = 4, score = 100
            //   03048d582c4300       | add                 eax, dword ptr [ecx*4 + 0x432c58]
            //   eb05                 | jmp                 7
            //   b8????????           |                     
            //   f6402820             | test                byte ptr [eax + 0x28], 0x20

        $sequence_7 = { 03148d582c4300 8b00 894218 8a441f04 }
            // n = 4, score = 100
            //   03148d582c4300       | add                 edx, dword ptr [ecx*4 + 0x432c58]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   894218               | mov                 dword ptr [edx + 0x18], eax
            //   8a441f04             | mov                 al, byte ptr [edi + ebx + 4]

        $sequence_8 = { 0f8592000000 8b433c 03c3 813850450000 }
            // n = 4, score = 100
            //   0f8592000000         | jne                 0x98
            //   8b433c               | mov                 eax, dword ptr [ebx + 0x3c]
            //   03c3                 | add                 eax, ebx
            //   813850450000         | cmp                 dword ptr [eax], 0x4550

        $sequence_9 = { 03048d582c4300 50 ff15???????? 5d }
            // n = 4, score = 100
            //   03048d582c4300       | add                 eax, dword ptr [ecx*4 + 0x432c58]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5d                   | pop                 ebp

        $sequence_10 = { 0135???????? 33c2 8d9335f23abd 0345d8 }
            // n = 4, score = 100
            //   0135????????         |                     
            //   33c2                 | xor                 eax, edx
            //   8d9335f23abd         | lea                 edx, [ebx - 0x42c50dcb]
            //   0345d8               | add                 eax, dword ptr [ebp - 0x28]

        $sequence_11 = { 010d???????? 0bf1 33f2 0375d4 }
            // n = 4, score = 100
            //   010d????????         |                     
            //   0bf1                 | or                  esi, ecx
            //   33f2                 | xor                 esi, edx
            //   0375d4               | add                 esi, dword ptr [ebp - 0x2c]

        $sequence_12 = { 8d458c 6a32 50 8d45f4 50 }
            // n = 5, score = 100
            //   8d458c               | lea                 eax, [ebp - 0x74]
            //   6a32                 | push                0x32
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax

        $sequence_13 = { 6a00 56 c745f00050fa7e e8???????? }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   56                   | push                esi
            //   c745f00050fa7e       | mov                 dword ptr [ebp - 0x10], 0x7efa5000
            //   e8????????           |                     

        $sequence_14 = { 884509 668b4508 5d c3 55 8bec 803d????????00 }
            // n = 7, score = 100
            //   884509               | mov                 byte ptr [ebp + 9], al
            //   668b4508             | mov                 ax, word ptr [ebp + 8]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   803d????????00       |                     

    condition:
        7 of them and filesize < 466944
}