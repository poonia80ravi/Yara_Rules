rule win_silon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.silon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silon"
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
        $sequence_0 = { e8???????? 83c408 8b95c0e7ffff 52 e8???????? 83c404 8b85d8e7ffff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b95c0e7ffff         | mov                 edx, dword ptr [ebp - 0x1840]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b85d8e7ffff         | mov                 eax, dword ptr [ebp - 0x1828]

        $sequence_1 = { 83c201 895594 8b4594 3b8578ffffff 0f839c010000 c78560fdffff00000000 }
            // n = 6, score = 200
            //   83c201               | add                 edx, 1
            //   895594               | mov                 dword ptr [ebp - 0x6c], edx
            //   8b4594               | mov                 eax, dword ptr [ebp - 0x6c]
            //   3b8578ffffff         | cmp                 eax, dword ptr [ebp - 0x88]
            //   0f839c010000         | jae                 0x1a2
            //   c78560fdffff00000000     | mov    dword ptr [ebp - 0x2a0], 0

        $sequence_2 = { e8???????? 8945fc 8b4528 50 8b4d24 51 8b5520 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4528               | mov                 eax, dword ptr [ebp + 0x28]
            //   50                   | push                eax
            //   8b4d24               | mov                 ecx, dword ptr [ebp + 0x24]
            //   51                   | push                ecx
            //   8b5520               | mov                 edx, dword ptr [ebp + 0x20]

        $sequence_3 = { 7e1c 8b4d08 034dfc 0fbe11 83fa61 7c20 8b4508 }
            // n = 7, score = 200
            //   7e1c                 | jle                 0x1e
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   0fbe11               | movsx               edx, byte ptr [ecx]
            //   83fa61               | cmp                 edx, 0x61
            //   7c20                 | jl                  0x22
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 035160 8955fc 8b450c c1e810 0fb7c8 85c9 751a }
            // n = 7, score = 200
            //   035160               | add                 edx, dword ptr [ecx + 0x60]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   c1e810               | shr                 eax, 0x10
            //   0fb7c8               | movzx               ecx, ax
            //   85c9                 | test                ecx, ecx
            //   751a                 | jne                 0x1c

        $sequence_5 = { 83c404 0fb745d4 50 8b8d48ffffff 51 8b9544ffffff 52 }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   0fb745d4             | movzx               eax, word ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   8b8d48ffffff         | mov                 ecx, dword ptr [ebp - 0xb8]
            //   51                   | push                ecx
            //   8b9544ffffff         | mov                 edx, dword ptr [ebp - 0xbc]
            //   52                   | push                edx

        $sequence_6 = { 8d85e4fdffff 50 6813000020 8b4df8 51 e8???????? 83c414 }
            // n = 7, score = 200
            //   8d85e4fdffff         | lea                 eax, [ebp - 0x21c]
            //   50                   | push                eax
            //   6813000020           | push                0x20000013
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_7 = { e8???????? 83c40c 8985c4efffff 83bdc4efffffff 7508 83c8ff }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8985c4efffff         | mov                 dword ptr [ebp - 0x103c], eax
            //   83bdc4efffffff       | cmp                 dword ptr [ebp - 0x103c], -1
            //   7508                 | jne                 0xa
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_8 = { 8b0d???????? 51 68???????? e8???????? 83c410 c78500feffff00000000 8b9504feffff }
            // n = 7, score = 200
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   c78500feffff00000000     | mov    dword ptr [ebp - 0x200], 0
            //   8b9504feffff         | mov                 edx, dword ptr [ebp - 0x1fc]

        $sequence_9 = { 0f8487000000 8b55fc 8b45fc 8b8a58080000 }
            // n = 4, score = 200
            //   0f8487000000         | je                  0x8d
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b8a58080000         | mov                 ecx, dword ptr [edx + 0x858]

    condition:
        7 of them and filesize < 122880
}