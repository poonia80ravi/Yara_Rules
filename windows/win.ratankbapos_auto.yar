rule win_ratankbapos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ratankbapos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratankbapos"
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
        $sequence_0 = { 8b4508 56 8d34c5303c0110 833e00 7513 50 }
            // n = 6, score = 300
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8d34c5303c0110       | lea                 esi, [eax*8 + 0x10013c30]
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7513                 | jne                 0x15
            //   50                   | push                eax

        $sequence_1 = { 894de8 c745f400000000 c745f005000000 c745f800000000 8b55f4 3b55f0 0f8397000000 }
            // n = 7, score = 300
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f005000000       | mov                 dword ptr [ebp - 0x10], 5
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   3b55f0               | cmp                 edx, dword ptr [ebp - 0x10]
            //   0f8397000000         | jae                 0x9d

        $sequence_2 = { 751c c74314ffffffff 5f 5e 33c0 5b 8b4dfc }
            // n = 7, score = 300
            //   751c                 | jne                 0x1e
            //   c74314ffffffff       | mov                 dword ptr [ebx + 0x14], 0xffffffff
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_3 = { 2b4ddc 894df4 8a55f4 80e207 8b45e0 0345f8 8a4838 }
            // n = 7, score = 300
            //   2b4ddc               | sub                 ecx, dword ptr [ebp - 0x24]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8a55f4               | mov                 dl, byte ptr [ebp - 0xc]
            //   80e207               | and                 dl, 7
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   0345f8               | add                 eax, dword ptr [ebp - 8]
            //   8a4838               | mov                 cl, byte ptr [eax + 0x38]

        $sequence_4 = { 6a00 0f95c2 6800000004 6a03 }
            // n = 4, score = 300
            //   6a00                 | push                0
            //   0f95c2               | setne               dl
            //   6800000004           | push                0x4000000
            //   6a03                 | push                3

        $sequence_5 = { 33c0 8a4201 83f825 7507 b801000000 eb71 }
            // n = 6, score = 300
            //   33c0                 | xor                 eax, eax
            //   8a4201               | mov                 al, byte ptr [edx + 1]
            //   83f825               | cmp                 eax, 0x25
            //   7507                 | jne                 9
            //   b801000000           | mov                 eax, 1
            //   eb71                 | jmp                 0x73

        $sequence_6 = { 8a4801 83f925 7532 8b5508 8b4202 8945f0 }
            // n = 6, score = 300
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   83f925               | cmp                 ecx, 0x25
            //   7532                 | jne                 0x34
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4202               | mov                 eax, dword ptr [edx + 2]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_7 = { ffd6 8b442410 3bc3 7403 50 ffd6 8b442414 }
            // n = 7, score = 300
            //   ffd6                 | call                esi
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   3bc3                 | cmp                 eax, ebx
            //   7403                 | je                  5
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_8 = { 8945c8 837dc800 7502 eb14 8b4dec }
            // n = 5, score = 300
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   837dc800             | cmp                 dword ptr [ebp - 0x38], 0
            //   7502                 | jne                 4
            //   eb14                 | jmp                 0x16
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_9 = { 895508 eb25 8b4508 33c9 8a08 81f9e9000000 }
            // n = 6, score = 300
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   eb25                 | jmp                 0x27
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   81f9e9000000         | cmp                 ecx, 0xe9

    condition:
        7 of them and filesize < 327680
}