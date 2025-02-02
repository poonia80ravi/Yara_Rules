rule win_astralocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.astralocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.astralocker"
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
        $sequence_0 = { b808000000 6bc80a 8b5508 33c0 33f6 }
            // n = 5, score = 500
            //   b808000000           | mov                 eax, 8
            //   6bc80a               | imul                ecx, eax, 0xa
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   33f6                 | xor                 esi, esi

        $sequence_1 = { 8b440a04 50 8b0c0a 51 e8???????? }
            // n = 5, score = 500
            //   8b440a04             | mov                 eax, dword ptr [edx + ecx + 4]
            //   50                   | push                eax
            //   8b0c0a               | mov                 ecx, dword ptr [edx + ecx]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_2 = { 891401 89740104 b808000000 6bc800 8b5508 8b440a04 50 }
            // n = 7, score = 500
            //   891401               | mov                 dword ptr [ecx + eax], edx
            //   89740104             | mov                 dword ptr [ecx + eax + 4], esi
            //   b808000000           | mov                 eax, 8
            //   6bc800               | imul                ecx, eax, 0
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b440a04             | mov                 eax, dword ptr [edx + ecx + 4]
            //   50                   | push                eax

        $sequence_3 = { 894dfc 837dfc0a 0f83dc000000 8b55fc 8b4508 }
            // n = 5, score = 500
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   837dfc0a             | cmp                 dword ptr [ebp - 4], 0xa
            //   0f83dc000000         | jae                 0xe2
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 8b0c0a 51 e8???????? 83c408 8945ec 8955f0 }
            // n = 6, score = 500
            //   8b0c0a               | mov                 ecx, dword ptr [edx + ecx]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx

        $sequence_5 = { 89040a 89740a04 c745fc00000000 eb09 8b4dfc 83c102 }
            // n = 6, score = 500
            //   89040a               | mov                 dword ptr [edx + ecx], eax
            //   89740a04             | mov                 dword ptr [edx + ecx + 4], esi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb09                 | jmp                 0xb
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c102               | add                 ecx, 2

        $sequence_6 = { 6bc20a 8b4d08 33d2 33f6 891401 }
            // n = 5, score = 500
            //   6bc20a               | imul                eax, edx, 0xa
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx
            //   33f6                 | xor                 esi, esi
            //   891401               | mov                 dword ptr [ecx + eax], edx

        $sequence_7 = { eb09 8b4dfc 83c102 894dfc 837dfc0a 0f83dc000000 }
            // n = 6, score = 500
            //   eb09                 | jmp                 0xb
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c102               | add                 ecx, 2
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   837dfc0a             | cmp                 dword ptr [ebp - 4], 0xa
            //   0f83dc000000         | jae                 0xe2

        $sequence_8 = { e8???????? 83c408 8945ec 8955f0 ba08000000 6bf200 8b45ec }
            // n = 7, score = 500
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   ba08000000           | mov                 edx, 8
            //   6bf200               | imul                esi, edx, 0
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_9 = { 51 e8???????? 83c408 8945ec 8955f0 ba08000000 6bf200 }
            // n = 7, score = 500
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   ba08000000           | mov                 edx, 8
            //   6bf200               | imul                esi, edx, 0

    condition:
        7 of them and filesize < 191488
}