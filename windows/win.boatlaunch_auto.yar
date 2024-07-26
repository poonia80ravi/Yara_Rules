rule win_boatlaunch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.boatlaunch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boatlaunch"
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
        $sequence_0 = { 85db 7452 53 e8???????? 8945fc 837dfc00 7443 }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   7452                 | je                  0x54
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   7443                 | je                  0x45

        $sequence_1 = { e8???????? 48837de000 7412 488b0d???????? }
            // n = 4, score = 100
            //   e8????????           |                     
            //   48837de000           | je                  0x1c6
            //   7412                 | dec                 eax
            //   488b0d????????       |                     

        $sequence_2 = { 83c404 d1e0 50 ff733c 6aff }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   d1e0                 | shl                 eax, 1
            //   50                   | push                eax
            //   ff733c               | push                dword ptr [ebx + 0x3c]
            //   6aff                 | push                -1

        $sequence_3 = { 894de0 ff75e0 6a00 ff35???????? e8???????? 8945e4 }
            // n = 6, score = 100
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_4 = { 448b45c4 4c8d4dc4 e8???????? 85c0 0f8493010000 488b75e0 48ad }
            // n = 7, score = 100
            //   448b45c4             | inc                 esp
            //   4c8d4dc4             | mov                 eax, dword ptr [ebp - 0x3c]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   0f8493010000         | mov                 dword ptr [ebp - 0x20], eax
            //   488b75e0             | dec                 eax
            //   48ad                 | cmp                 dword ptr [ebp - 0x20], 0

        $sequence_5 = { 4c8d4d10 e8???????? 85c0 7516 488b4dd0 488d55d8 }
            // n = 6, score = 100
            //   4c8d4d10             | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [ebp + 0x10], eax
            //   7516                 | dec                 eax
            //   488b4dd0             | mov                 dword ptr [ebp + 0x18], 0
            //   488d55d8             | dec                 eax

        $sequence_6 = { 488b4df8 49c7c104000000 48c744242000000000 e8???????? 85c0 7408 488bcb }
            // n = 7, score = 100
            //   488b4df8             | dec                 eax
            //   49c7c104000000       | mov                 ecx, dword ptr [ebp - 8]
            //   48c744242000000000     | dec    ecx
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, 4
            //   7408                 | dec                 eax
            //   488bcb               | mov                 dword ptr [esp + 0x20], 0

        $sequence_7 = { 56 57 c745fc00000000 c745f400000000 c745e400000000 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0

        $sequence_8 = { 8d45f8 50 e8???????? 3d0b0000c0 }
            // n = 4, score = 100
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   3d0b0000c0           | cmp                 eax, 0xc000000b

        $sequence_9 = { 85db 0f840d010000 d1e3 8d85e0eeffff 50 e8???????? 83c404 }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   0f840d010000         | je                  0x113
            //   d1e3                 | shl                 ebx, 1
            //   8d85e0eeffff         | lea                 eax, [ebp - 0x1120]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_10 = { ff733c e8???????? 83c404 ff733c }
            // n = 4, score = 100
            //   ff733c               | push                dword ptr [ebx + 0x3c]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   ff733c               | push                dword ptr [ebx + 0x3c]

        $sequence_11 = { 48c7c208000000 448b45c4 e8???????? 488945e0 48837de000 0f84b3010000 488b8d50110000 }
            // n = 7, score = 100
            //   48c7c208000000       | test                eax, eax
            //   448b45c4             | je                  0xa
            //   e8????????           |                     
            //   488945e0             | dec                 eax
            //   48837de000           | mov                 ecx, ebx
            //   0f84b3010000         | dec                 eax
            //   488b8d50110000       | mov                 edx, 8

        $sequence_12 = { 488bfe b940000000 48ad 4885c0 7508 488b4530 48ab }
            // n = 7, score = 100
            //   488bfe               | dec                 eax
            //   b940000000           | lodsd               eax, dword ptr [esi]
            //   48ad                 | dec                 eax
            //   4885c0               | cmp                 dword ptr [ebp - 0x20], 0
            //   7508                 | je                  0x14
            //   488b4530             | dec                 eax
            //   48ab                 | mov                 eax, dword ptr [ebp + 0x80]

        $sequence_13 = { 57 c745fc00000000 8b4508 8945f4 c745f800000000 8d5ddc }
            // n = 6, score = 100
            //   57                   | push                edi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   8d5ddc               | lea                 ebx, [ebp - 0x24]

        $sequence_14 = { 488b8580000000 48894510 48c7451800000000 488d4de0 c70130000000 }
            // n = 5, score = 100
            //   488b8580000000       | mov                 ecx, dword ptr [ebp + 0x1150]
            //   48894510             | inc                 esp
            //   48c7451800000000     | mov                 eax, dword ptr [ebp - 0x3c]
            //   488d4de0             | dec                 esp
            //   c70130000000         | lea                 ecx, [ebp - 0x3c]

        $sequence_15 = { 488d6528 415b 415a 4159 }
            // n = 4, score = 100
            //   488d6528             | test                eax, eax
            //   415b                 | je                  0x19f
            //   415a                 | dec                 eax
            //   4159                 | mov                 esi, dword ptr [ebp - 0x20]

    condition:
        7 of them and filesize < 33792
}