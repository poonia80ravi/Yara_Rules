rule win_chinoxy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.chinoxy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chinoxy"
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
        $sequence_0 = { 56 57 895c240c c703???????? c744241803000000 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   895c240c             | mov                 dword ptr [esp + 0xc], ebx
            //   c703????????         |                     
            //   c744241803000000     | mov                 dword ptr [esp + 0x18], 3

        $sequence_1 = { 8d742418 c1e902 f3a5 8bc8 83e103 43 f3a4 }
            // n = 7, score = 100
            //   8d742418             | lea                 esi, [esp + 0x18]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   43                   | inc                 ebx
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]

        $sequence_2 = { 8b842478050000 48 0f85eb020000 53 55 56 57 }
            // n = 7, score = 100
            //   8b842478050000       | mov                 eax, dword ptr [esp + 0x578]
            //   48                   | dec                 eax
            //   0f85eb020000         | jne                 0x2f1
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_3 = { 5d 5b 59 c20800 8b442404 83ec10 53 }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   c20800               | ret                 8
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   83ec10               | sub                 esp, 0x10
            //   53                   | push                ebx

        $sequence_4 = { 5f 8bc3 5e 5b c20400 8b4f08 8b06 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   8bc3                 | mov                 eax, ebx
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c20400               | ret                 4
            //   8b4f08               | mov                 ecx, dword ptr [edi + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_5 = { 760d 56 8bcf e8???????? 46 }
            // n = 5, score = 100
            //   760d                 | jbe                 0xf
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   46                   | inc                 esi

        $sequence_6 = { 6a00 8bcf e8???????? 8b8690800200 8b3d???????? 50 ffd7 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b8690800200         | mov                 eax, dword ptr [esi + 0x28090]
            //   8b3d????????         |                     
            //   50                   | push                eax
            //   ffd7                 | call                edi

        $sequence_7 = { 897e2c 897e30 897e54 897e58 e8???????? 8d4678 }
            // n = 6, score = 100
            //   897e2c               | mov                 dword ptr [esi + 0x2c], edi
            //   897e30               | mov                 dword ptr [esi + 0x30], edi
            //   897e54               | mov                 dword ptr [esi + 0x54], edi
            //   897e58               | mov                 dword ptr [esi + 0x58], edi
            //   e8????????           |                     
            //   8d4678               | lea                 eax, [esi + 0x78]

        $sequence_8 = { c7863420000004000000 c7863420000007000000 8b86b8200000 8d9eb0200000 3bc3 89430c 8b5008 }
            // n = 7, score = 100
            //   c7863420000004000000     | mov    dword ptr [esi + 0x2034], 4
            //   c7863420000007000000     | mov    dword ptr [esi + 0x2034], 7
            //   8b86b8200000         | mov                 eax, dword ptr [esi + 0x20b8]
            //   8d9eb0200000         | lea                 ebx, [esi + 0x20b0]
            //   3bc3                 | cmp                 eax, ebx
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   8b5008               | mov                 edx, dword ptr [eax + 8]

        $sequence_9 = { 896c2434 e8???????? 83c414 85c0 7528 }
            // n = 5, score = 100
            //   896c2434             | mov                 dword ptr [esp + 0x34], ebp
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7528                 | jne                 0x2a

    condition:
        7 of them and filesize < 1138688
}