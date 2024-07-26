rule win_nymaim2_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.nymaim2."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nymaim2"
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
        $sequence_0 = { e8???????? 59 895dec 59 8d4df0 c645fc03 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   59                   | pop                 ecx
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   e8????????           |                     

        $sequence_1 = { e9???????? 8d8d34ffffff e9???????? 8d8d38ffffff e9???????? 8d8d14ffffff e9???????? }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8d8d34ffffff         | lea                 ecx, [ebp - 0xcc]
            //   e9????????           |                     
            //   8d8d38ffffff         | lea                 ecx, [ebp - 0xc8]
            //   e9????????           |                     
            //   8d8d14ffffff         | lea                 ecx, [ebp - 0xec]
            //   e9????????           |                     

        $sequence_2 = { ebf5 b8???????? e8???????? 51 56 8bf1 8975f0 }
            // n = 7, score = 200
            //   ebf5                 | jmp                 0xfffffff7
            //   b8????????           |                     
            //   e8????????           |                     
            //   51                   | push                ecx
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi

        $sequence_3 = { 8d4de0 c745fc01000000 e8???????? 834dfcff 8d4ddc e8???????? 53 }
            // n = 7, score = 200
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     
            //   53                   | push                ebx

        $sequence_4 = { dd1c24 53 57 e8???????? 50 a1???????? 83c040 }
            // n = 7, score = 200
            //   dd1c24               | fstp                qword ptr [esp]
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     
            //   50                   | push                eax
            //   a1????????           |                     
            //   83c040               | add                 eax, 0x40

        $sequence_5 = { e8???????? 8bc8 c645fc06 e8???????? 50 53 8d4dc0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6
            //   e8????????           |                     
            //   50                   | push                eax
            //   53                   | push                ebx
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]

        $sequence_6 = { ff10 81c6d4010000 8d4dc8 56 68???????? e8???????? 50 }
            // n = 7, score = 200
            //   ff10                 | call                dword ptr [eax]
            //   81c6d4010000         | add                 esi, 0x1d4
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_7 = { e8???????? 8d4de4 c7042404010000 e8???????? 8365fc00 6a00 8bc8 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   c7042404010000       | mov                 dword ptr [esp], 0x104
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   6a00                 | push                0
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { 57 50 897d08 ff760c ff7604 53 ff15???????? }
            // n = 7, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   897d08               | mov                 dword ptr [ebp + 8], edi
            //   ff760c               | push                dword ptr [esi + 0xc]
            //   ff7604               | push                dword ptr [esi + 4]
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_9 = { e8???????? 50 8d4d08 e8???????? 85c0 0f9dc3 8d4d9c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f9dc3               | setge               bl
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]

    condition:
        7 of them and filesize < 753664
}