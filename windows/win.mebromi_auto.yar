rule win_mebromi_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mebromi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mebromi"
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
        $sequence_0 = { 8b4508 ff348520712900 ff15???????? 5d c3 55 }
            // n = 6, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff348520712900       | push                dword ptr [eax*4 + 0x297120]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_1 = { e8???????? 68???????? 56 e8???????? 83c418 6a01 58 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   6a01                 | push                1
            //   58                   | pop                 eax

        $sequence_2 = { c1f905 83e01f 8b0c8d20a12900 8d04c0 8d0481 8b4dfc }
            // n = 6, score = 100
            //   c1f905               | sar                 ecx, 5
            //   83e01f               | and                 eax, 0x1f
            //   8b0c8d20a12900       | mov                 ecx, dword ptr [ecx*4 + 0x29a120]
            //   8d04c0               | lea                 eax, [eax + eax*8]
            //   8d0481               | lea                 eax, [ecx + eax*4]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_3 = { 83e203 83f908 7229 f3a5 ff2495082c2900 }
            // n = 5, score = 100
            //   83e203               | and                 edx, 3
            //   83f908               | cmp                 ecx, 8
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff2495082c2900       | jmp                 dword ptr [edx*4 + 0x292c08]

        $sequence_4 = { 50 a3???????? e8???????? 8db67c722900 bf???????? a5 a5 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   a3????????           |                     
            //   e8????????           |                     
            //   8db67c722900         | lea                 esi, [esi + 0x29727c]
            //   bf????????           |                     
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_5 = { 8b7d08 8d05549d2900 83780800 753b b0ff 8bff }
            // n = 6, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d05549d2900         | lea                 eax, [0x299d54]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   753b                 | jne                 0x3d
            //   b0ff                 | mov                 al, 0xff
            //   8bff                 | mov                 edi, edi

        $sequence_6 = { 68ff010f00 50 50 ff742438 ff15???????? 3bc6 }
            // n = 6, score = 100
            //   68ff010f00           | push                0xf01ff
            //   50                   | push                eax
            //   50                   | push                eax
            //   ff742438             | push                dword ptr [esp + 0x38]
            //   ff15????????         |                     
            //   3bc6                 | cmp                 eax, esi

        $sequence_7 = { 740d ffd7 3d22040000 7404 33ff eb03 6a01 }
            // n = 7, score = 100
            //   740d                 | je                  0xf
            //   ffd7                 | call                edi
            //   3d22040000           | cmp                 eax, 0x422
            //   7404                 | je                  6
            //   33ff                 | xor                 edi, edi
            //   eb03                 | jmp                 5
            //   6a01                 | push                1

        $sequence_8 = { ffd7 3d22040000 7404 33ff eb03 6a01 }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   3d22040000           | cmp                 eax, 0x422
            //   7404                 | je                  6
            //   33ff                 | xor                 edi, edi
            //   eb03                 | jmp                 5
            //   6a01                 | push                1

        $sequence_9 = { c1e604 aa 8d9e88722900 803b00 8bcb 742c 8a5101 }
            // n = 7, score = 100
            //   c1e604               | shl                 esi, 4
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d9e88722900         | lea                 ebx, [esi + 0x297288]
            //   803b00               | cmp                 byte ptr [ebx], 0
            //   8bcb                 | mov                 ecx, ebx
            //   742c                 | je                  0x2e
            //   8a5101               | mov                 dl, byte ptr [ecx + 1]

    condition:
        7 of them and filesize < 106496
}