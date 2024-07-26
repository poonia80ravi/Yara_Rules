rule win_gratem_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gratem."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gratem"
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
        $sequence_0 = { 8d4c244c 51 6a00 6a00 68???????? 6a00 55 }
            // n = 7, score = 100
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   6a00                 | push                0
            //   55                   | push                ebp

        $sequence_1 = { 83e61f c1e606 033485c0d84000 8b45e4 8b00 }
            // n = 5, score = 100
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   033485c0d84000       | add                 esi, dword ptr [eax*4 + 0x40d8c0]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_2 = { 663bc2 0f84d6040000 0fb7048d64bc4000 41 6685c0 }
            // n = 5, score = 100
            //   663bc2               | cmp                 ax, dx
            //   0f84d6040000         | je                  0x4dc
            //   0fb7048d64bc4000     | movzx               eax, word ptr [ecx*4 + 0x40bc64]
            //   41                   | inc                 ecx
            //   6685c0               | test                ax, ax

        $sequence_3 = { 6a00 8d542414 52 8d442440 }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   52                   | push                edx
            //   8d442440             | lea                 eax, [esp + 0x40]

        $sequence_4 = { 8d442440 50 6813000020 53 c744242404000000 }
            // n = 5, score = 100
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   6813000020           | push                0x20000013
            //   53                   | push                ebx
            //   c744242404000000     | mov                 dword ptr [esp + 0x24], 4

        $sequence_5 = { 663bc2 0f84c8000000 0fb7048d64bc4000 41 6685c0 }
            // n = 5, score = 100
            //   663bc2               | cmp                 ax, dx
            //   0f84c8000000         | je                  0xce
            //   0fb7048d64bc4000     | movzx               eax, word ptr [ecx*4 + 0x40bc64]
            //   41                   | inc                 ecx
            //   6685c0               | test                ax, ax

        $sequence_6 = { 663bc2 0f84dd020000 0fb7048d64bc4000 41 6685c0 }
            // n = 5, score = 100
            //   663bc2               | cmp                 ax, dx
            //   0f84dd020000         | je                  0x2e3
            //   0fb7048d64bc4000     | movzx               eax, word ptr [ecx*4 + 0x40bc64]
            //   41                   | inc                 ecx
            //   6685c0               | test                ax, ax

        $sequence_7 = { 6805010000 8d442404 6a00 50 e8???????? 83c40c 6805010000 }
            // n = 7, score = 100
            //   6805010000           | push                0x105
            //   8d442404             | lea                 eax, [esp + 4]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6805010000           | push                0x105

        $sequence_8 = { bab11a0000 663bc2 0f84dd020000 0fb7048d64bc4000 }
            // n = 4, score = 100
            //   bab11a0000           | mov                 edx, 0x1ab1
            //   663bc2               | cmp                 ax, dx
            //   0f84dd020000         | je                  0x2e3
            //   0fb7048d64bc4000     | movzx               eax, word ptr [ecx*4 + 0x40bc64]

        $sequence_9 = { 8bc6 c1f805 83e61f c1e606 033485c0d84000 }
            // n = 5, score = 100
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   033485c0d84000       | add                 esi, dword ptr [eax*4 + 0x40d8c0]

    condition:
        7 of them and filesize < 155648
}