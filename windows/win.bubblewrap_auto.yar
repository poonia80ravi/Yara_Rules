rule win_bubblewrap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bubblewrap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bubblewrap"
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
        $sequence_0 = { 8a4c1464 8d441464 8b542430 81e2ff000000 8a541464 }
            // n = 5, score = 100
            //   8a4c1464             | mov                 cl, byte ptr [esp + edx + 0x64]
            //   8d441464             | lea                 eax, [esp + edx + 0x64]
            //   8b542430             | mov                 edx, dword ptr [esp + 0x30]
            //   81e2ff000000         | and                 edx, 0xff
            //   8a541464             | mov                 dl, byte ptr [esp + edx + 0x64]

        $sequence_1 = { 0f844e010000 8b6c2410 85ed 0f8c42010000 8b442414 }
            // n = 5, score = 100
            //   0f844e010000         | je                  0x154
            //   8b6c2410             | mov                 ebp, dword ptr [esp + 0x10]
            //   85ed                 | test                ebp, ebp
            //   0f8c42010000         | jl                  0x148
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_2 = { b920000000 8d742434 bf???????? 89540439 a1???????? 8b15???????? 83c404 }
            // n = 7, score = 100
            //   b920000000           | mov                 ecx, 0x20
            //   8d742434             | lea                 esi, [esp + 0x34]
            //   bf????????           |                     
            //   89540439             | mov                 dword ptr [esp + eax + 0x39], edx
            //   a1????????           |                     
            //   8b15????????         |                     
            //   83c404               | add                 esp, 4

        $sequence_3 = { 83e103 6800b00400 f3a4 8d4c2414 50 }
            // n = 5, score = 100
            //   83e103               | and                 ecx, 3
            //   6800b00400           | push                0x4b000
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   50                   | push                eax

        $sequence_4 = { 8d442438 8974241c 50 57 ffd5 }
            // n = 5, score = 100
            //   8d442438             | lea                 eax, [esp + 0x38]
            //   8974241c             | mov                 dword ptr [esp + 0x1c], esi
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd5                 | call                ebp

        $sequence_5 = { b940000000 33c0 8dbc24a9000000 c68424a800000000 f3ab 66ab 8d9424a8000000 }
            // n = 7, score = 100
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8dbc24a9000000       | lea                 edi, [esp + 0xa9]
            //   c68424a800000000     | mov                 byte ptr [esp + 0xa8], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8d9424a8000000       | lea                 edx, [esp + 0xa8]

        $sequence_6 = { ffd6 68???????? ffd6 8b5c241c }
            // n = 4, score = 100
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8b5c241c             | mov                 ebx, dword ptr [esp + 0x1c]

        $sequence_7 = { 8bd7 d1e9 c1e21f 0bca }
            // n = 4, score = 100
            //   8bd7                 | mov                 edx, edi
            //   d1e9                 | shr                 ecx, 1
            //   c1e21f               | shl                 edx, 0x1f
            //   0bca                 | or                  ecx, edx

        $sequence_8 = { 68???????? 52 ffd6 b900020000 33c0 }
            // n = 5, score = 100
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   b900020000           | mov                 ecx, 0x200
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { c1e902 f3a5 8bca 83e103 f3a4 e8???????? 8b0d???????? }
            // n = 7, score = 100
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   e8????????           |                     
            //   8b0d????????         |                     

    condition:
        7 of them and filesize < 57136
}