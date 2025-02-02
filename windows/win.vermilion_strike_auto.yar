rule win_vermilion_strike_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.vermilion_strike."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vermilion_strike"
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
        $sequence_0 = { e8???????? 99 f7fe 53 8d742420 8bfa e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   53                   | push                ebx
            //   8d742420             | lea                 esi, [esp + 0x20]
            //   8bfa                 | mov                 edi, edx
            //   e8????????           |                     

        $sequence_1 = { c746180f000000 c7461400000000 56 c6450000 e8???????? 83c404 }
            // n = 6, score = 200
            //   c746180f000000       | mov                 dword ptr [esi + 0x18], 0xf
            //   c7461400000000       | mov                 dword ptr [esi + 0x14], 0
            //   56                   | push                esi
            //   c6450000             | mov                 byte ptr [ebp], 0
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_2 = { 6a00 56 e8???????? 8b44242c bf10000000 83c410 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   bf10000000           | mov                 edi, 0x10
            //   83c410               | add                 esp, 0x10

        $sequence_3 = { 56 e8???????? 8b442428 8bc8 c1f918 884c2428 8bd0 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   8bc8                 | mov                 ecx, eax
            //   c1f918               | sar                 ecx, 0x18
            //   884c2428             | mov                 byte ptr [esp + 0x28], cl
            //   8bd0                 | mov                 edx, eax

        $sequence_4 = { 83c404 41 51 33ff }
            // n = 4, score = 200
            //   83c404               | add                 esp, 4
            //   41                   | inc                 ecx
            //   51                   | push                ecx
            //   33ff                 | xor                 edi, edi

        $sequence_5 = { 8b94248c000000 52 e8???????? 83c404 89ac24a0000000 }
            // n = 5, score = 200
            //   8b94248c000000       | mov                 edx, dword ptr [esp + 0x8c]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   89ac24a0000000       | mov                 dword ptr [esp + 0xa0], ebp

        $sequence_6 = { 52 89442420 ffd7 85c0 7503 5f 59 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5
            //   5f                   | pop                 edi
            //   59                   | pop                 ecx

        $sequence_7 = { 8bf8 85ff 7420 83fa08 7204 8b08 eb02 }
            // n = 7, score = 200
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   7420                 | je                  0x22
            //   83fa08               | cmp                 edx, 8
            //   7204                 | jb                  6
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   eb02                 | jmp                 4

        $sequence_8 = { 760d e8???????? 8b442424 8b4c2420 8bf9 3bc8 7605 }
            // n = 7, score = 200
            //   760d                 | jbe                 0xf
            //   e8????????           |                     
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   8bf9                 | mov                 edi, ecx
            //   3bc8                 | cmp                 ecx, eax
            //   7605                 | jbe                 7

        $sequence_9 = { 8d7c2440 85f6 7509 8bc3 e8???????? eb2b 8b8c24a0000000 }
            // n = 7, score = 200
            //   8d7c2440             | lea                 edi, [esp + 0x40]
            //   85f6                 | test                esi, esi
            //   7509                 | jne                 0xb
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   eb2b                 | jmp                 0x2d
            //   8b8c24a0000000       | mov                 ecx, dword ptr [esp + 0xa0]

    condition:
        7 of them and filesize < 540672
}