rule win_maze_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.maze."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maze"
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
        $sequence_0 = { c745f000000000 eb17 60 8b7d08 }
            // n = 4, score = 2400
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   eb17                 | jmp                 0x19
            //   60                   | pushal              
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_1 = { 83ec10 8b4510 8b4d0c 8b5508 837d0800 8945ec 894de8 }
            // n = 7, score = 2400
            //   83ec10               | sub                 esp, 0x10
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx

        $sequence_2 = { 894de8 8955e4 7509 c745f000000000 eb17 }
            // n = 5, score = 2400
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   7509                 | jne                 0xb
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   eb17                 | jmp                 0x19

        $sequence_3 = { 53 57 56 83ec10 8b4510 8b4d0c }
            // n = 6, score = 2400
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   83ec10               | sub                 esp, 0x10
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_4 = { 8945f0 c745f000000000 8b45f0 83c410 5e 5f 5b }
            // n = 7, score = 2400
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83c410               | add                 esp, 0x10
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx

        $sequence_5 = { 60 8b7d08 8b4d10 8b450c f3aa 61 8945f0 }
            // n = 7, score = 2400
            //   60                   | pushal              
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   61                   | popal               
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_6 = { 89c7 8b842458010000 83d600 660f6eeb 0fa4ce06 81e1000000fc }
            // n = 6, score = 2300
            //   89c7                 | mov                 edi, eax
            //   8b842458010000       | mov                 eax, dword ptr [esp + 0x158]
            //   83d600               | adc                 esi, 0
            //   660f6eeb             | movd                xmm5, ebx
            //   0fa4ce06             | shld                esi, ecx, 6
            //   81e1000000fc         | and                 ecx, 0xfc000000

        $sequence_7 = { 89c7 c1fa1a 81e7ffffff03 03542408 }
            // n = 4, score = 2300
            //   89c7                 | mov                 edi, eax
            //   c1fa1a               | sar                 edx, 0x1a
            //   81e7ffffff03         | and                 edi, 0x3ffffff
            //   03542408             | add                 edx, dword ptr [esp + 8]

        $sequence_8 = { 41 41 41 41 41 41 }
            // n = 6, score = 1600
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx

        $sequence_9 = { 3145f8 31e8 898524010000 53 }
            // n = 4, score = 1400
            //   3145f8               | xor                 dword ptr [ebp - 8], eax
            //   31e8                 | xor                 eax, ebp
            //   898524010000         | mov                 dword ptr [ebp + 0x124], eax
            //   53                   | push                ebx

        $sequence_10 = { 0fb695cefeffff 8b4508 8b8c8800080000 8b4508 }
            // n = 4, score = 100
            //   0fb695cefeffff       | movzx               edx, byte ptr [ebp - 0x132]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b8c8800080000       | mov                 ecx, dword ptr [eax + ecx*4 + 0x800]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_11 = { 8b4508 8b8c900c080000 038d70feffff 8b9578feffff 339574feffff }
            // n = 5, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b8c900c080000       | mov                 ecx, dword ptr [eax + edx*4 + 0x80c]
            //   038d70feffff         | add                 ecx, dword ptr [ebp - 0x190]
            //   8b9578feffff         | mov                 edx, dword ptr [ebp - 0x188]
            //   339574feffff         | xor                 edx, dword ptr [ebp - 0x18c]

        $sequence_12 = { 399848a94100 0f84e8000000 41 83c030 894de4 }
            // n = 5, score = 100
            //   399848a94100         | cmp                 dword ptr [eax + 0x41a948], ebx
            //   0f84e8000000         | je                  0xee
            //   41                   | inc                 ecx
            //   83c030               | add                 eax, 0x30
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx

        $sequence_13 = { 8b4508 8b941000100000 c1ea0a 0bca 898d64ffffff b804000000 6bc80d }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b941000100000       | mov                 edx, dword ptr [eax + edx + 0x1000]
            //   c1ea0a               | shr                 edx, 0xa
            //   0bca                 | or                  ecx, edx
            //   898d64ffffff         | mov                 dword ptr [ebp - 0x9c], ecx
            //   b804000000           | mov                 eax, 4
            //   6bc80d               | imul                ecx, eax, 0xd

        $sequence_14 = { 8b4508 8b4c9020 038d4cffffff 8b9554ffffff 339550ffffff 03ca 338d48ffffff }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4c9020             | mov                 ecx, dword ptr [eax + edx*4 + 0x20]
            //   038d4cffffff         | add                 ecx, dword ptr [ebp - 0xb4]
            //   8b9554ffffff         | mov                 edx, dword ptr [ebp - 0xac]
            //   339550ffffff         | xor                 edx, dword ptr [ebp - 0xb0]
            //   03ca                 | add                 ecx, edx
            //   338d48ffffff         | xor                 ecx, dword ptr [ebp - 0xb8]

        $sequence_15 = { 8b4d10 8b0401 334415b4 b904000000 6bd10d 8b4d14 890411 }
            // n = 7, score = 100
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b0401               | mov                 eax, dword ptr [ecx + eax]
            //   334415b4             | xor                 eax, dword ptr [ebp + edx - 0x4c]
            //   b904000000           | mov                 ecx, 4
            //   6bd10d               | imul                edx, ecx, 0xd
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   890411               | mov                 dword ptr [ecx + edx], eax

        $sequence_16 = { 8b840a40100000 c1e810 8885defdffff 0fb68ddffdffff 0fb695defdffff 8b4508 8b0c88 }
            // n = 7, score = 100
            //   8b840a40100000       | mov                 eax, dword ptr [edx + ecx + 0x1040]
            //   c1e810               | shr                 eax, 0x10
            //   8885defdffff         | mov                 byte ptr [ebp - 0x222], al
            //   0fb68ddffdffff       | movzx               ecx, byte ptr [ebp - 0x221]
            //   0fb695defdffff       | movzx               edx, byte ptr [ebp - 0x222]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0c88               | mov                 ecx, dword ptr [eax + ecx*4]

        $sequence_17 = { 89840a40100000 8b4dfc 8b5508 8b85ccfdffff 33848a2c080000 b904000000 6bd10b }
            // n = 7, score = 100
            //   89840a40100000       | mov                 dword ptr [edx + ecx + 0x1040], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b85ccfdffff         | mov                 eax, dword ptr [ebp - 0x234]
            //   33848a2c080000       | xor                 eax, dword ptr [edx + ecx*4 + 0x82c]
            //   b904000000           | mov                 ecx, 4
            //   6bd10b               | imul                edx, ecx, 0xb

    condition:
        7 of them and filesize < 2318336
}