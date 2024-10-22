rule win_shipshape_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.shipshape."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shipshape"
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
        $sequence_0 = { 0f8434020000 8d8424e4000000 68???????? 50 }
            // n = 4, score = 100
            //   0f8434020000         | je                  0x23a
            //   8d8424e4000000       | lea                 eax, [esp + 0xe4]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_1 = { 6a3b 68???????? e8???????? 83c440 6a4e }
            // n = 5, score = 100
            //   6a3b                 | push                0x3b
            //   68????????           |                     
            //   e8????????           |                     
            //   83c440               | add                 esp, 0x40
            //   6a4e                 | push                0x4e

        $sequence_2 = { 51 55 ff15???????? 8d542420 52 ff15???????? }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   8d542420             | lea                 edx, [esp + 0x20]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_3 = { 8bc8 83e103 f3a4 8d8c24fc010000 51 e8???????? 83c408 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d8c24fc010000       | lea                 ecx, [esp + 0x1fc]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_4 = { 0fb70445b2b44000 23442408 eb02 33c0 85c0 }
            // n = 5, score = 100
            //   0fb70445b2b44000     | movzx               eax, word ptr [eax*2 + 0x40b4b2]
            //   23442408             | and                 eax, dword ptr [esp + 8]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8d84244c040000 68???????? 50 e8???????? 8d8c2454040000 51 }
            // n = 6, score = 100
            //   8d84244c040000       | lea                 eax, [esp + 0x44c]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8c2454040000       | lea                 ecx, [esp + 0x454]
            //   51                   | push                ecx

        $sequence_6 = { 8d4508 8db67cb74000 6a00 50 }
            // n = 4, score = 100
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8db67cb74000         | lea                 esi, [esi + 0x40b77c]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_7 = { 6840420f00 51 52 e8???????? 50 }
            // n = 5, score = 100
            //   6840420f00           | push                0xf4240
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_8 = { f7d1 2bf9 8d9424fc050000 8bf7 }
            // n = 4, score = 100
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8d9424fc050000       | lea                 edx, [esp + 0x5fc]
            //   8bf7                 | mov                 esi, edi

        $sequence_9 = { c1e902 83e203 83f908 7229 f3a5 ff249568754000 8bc7 }
            // n = 7, score = 100
            //   c1e902               | shr                 ecx, 2
            //   83e203               | and                 edx, 3
            //   83f908               | cmp                 ecx, 8
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff249568754000       | jmp                 dword ptr [edx*4 + 0x407568]
            //   8bc7                 | mov                 eax, edi

    condition:
        7 of them and filesize < 338386
}