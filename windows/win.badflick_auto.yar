rule win_badflick_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.badflick."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badflick"
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
        $sequence_0 = { 83c420 6a00 ff15???????? ffd6 833806 }
            // n = 5, score = 100
            //   83c420               | add                 esp, 0x20
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   ffd6                 | call                esi
            //   833806               | cmp                 dword ptr [eax], 6

        $sequence_1 = { e8???????? 40 50 57 bb???????? 53 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   57                   | push                edi
            //   bb????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_2 = { c3 55 8bec 83ec1c 57 6a06 6a01 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   57                   | push                edi
            //   6a06                 | push                6
            //   6a01                 | push                1

        $sequence_3 = { f3a5 e8???????? 59 e8???????? 6a10 68???????? }
            // n = 6, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   6a10                 | push                0x10
            //   68????????           |                     

        $sequence_4 = { 8b7d08 8d4710 50 6a42 e8???????? 8bf0 }
            // n = 6, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d4710               | lea                 eax, [edi + 0x10]
            //   50                   | push                eax
            //   6a42                 | push                0x42
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 8bec 81ec98030000 53 56 57 8b7d08 57 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   81ec98030000         | sub                 esp, 0x398
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   57                   | push                edi

        $sequence_6 = { 48 7445 48 0f8504010000 8d7306 56 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   7445                 | je                  0x47
            //   48                   | dec                 eax
            //   0f8504010000         | jne                 0x10a
            //   8d7306               | lea                 esi, [ebx + 6]
            //   56                   | push                esi

        $sequence_7 = { eb2a 803843 7519 8b4805 3b4df8 7511 39780d }
            // n = 7, score = 100
            //   eb2a                 | jmp                 0x2c
            //   803843               | cmp                 byte ptr [eax], 0x43
            //   7519                 | jne                 0x1b
            //   8b4805               | mov                 ecx, dword ptr [eax + 5]
            //   3b4df8               | cmp                 ecx, dword ptr [ebp - 8]
            //   7511                 | jne                 0x13
            //   39780d               | cmp                 dword ptr [eax + 0xd], edi

        $sequence_8 = { ff75f8 ff75e4 ff15???????? ebce 55 8bec 56 }
            // n = 7, score = 100
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ff15????????         |                     
            //   ebce                 | jmp                 0xffffffd0
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi

        $sequence_9 = { c745c040000000 ff15???????? 85c0 7502 c9 c3 }
            // n = 6, score = 100
            //   c745c040000000       | mov                 dword ptr [ebp - 0x40], 0x40
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   c9                   | leave               
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 81920
}