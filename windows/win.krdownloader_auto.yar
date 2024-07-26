rule win_krdownloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.krdownloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krdownloader"
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
        $sequence_0 = { 51 894dfc 8b45fc 83b8580d030000 7513 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83b8580d030000       | cmp                 dword ptr [eax + 0x30d58], 0
            //   7513                 | jne                 0x15

        $sequence_1 = { 6a01 68???????? 8b4d08 034dfc }
            // n = 4, score = 200
            //   6a01                 | push                1
            //   68????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]

        $sequence_2 = { 51 894dfc 8b4508 833800 7415 8b4d08 8b11 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   833800               | cmp                 dword ptr [eax], 0
            //   7415                 | je                  0x17
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b11                 | mov                 edx, dword ptr [ecx]

        $sequence_3 = { 83783400 0f8482000000 c745f000000000 c745f400000000 eb09 8b4df4 }
            // n = 6, score = 200
            //   83783400             | cmp                 dword ptr [eax + 0x34], 0
            //   0f8482000000         | je                  0x88
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   eb09                 | jmp                 0xb
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_4 = { 8b4834 51 ff15???????? 8b55fc 894210 68???????? 8b45fc }
            // n = 7, score = 200
            //   8b4834               | mov                 ecx, dword ptr [eax + 0x34]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   894210               | mov                 dword ptr [edx + 0x10], eax
            //   68????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_5 = { 8b4510 8945f8 8b4df8 894df4 8b55f4 }
            // n = 5, score = 200
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_6 = { a0???????? 8885f0fbffff 68ff030000 6a00 8d8df1fbffff }
            // n = 5, score = 200
            //   a0????????           |                     
            //   8885f0fbffff         | mov                 byte ptr [ebp - 0x410], al
            //   68ff030000           | push                0x3ff
            //   6a00                 | push                0
            //   8d8df1fbffff         | lea                 ecx, [ebp - 0x40f]

        $sequence_7 = { 8955b0 8b45fc 8945c4 8b4dc4 }
            // n = 4, score = 200
            //   8955b0               | mov                 dword ptr [ebp - 0x50], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   8b4dc4               | mov                 ecx, dword ptr [ebp - 0x3c]

        $sequence_8 = { 50 8b0d???????? 8b5114 ffd2 85c0 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8b0d????????         |                     
            //   8b5114               | mov                 edx, dword ptr [ecx + 0x14]
            //   ffd2                 | call                edx
            //   85c0                 | test                eax, eax

        $sequence_9 = { 81e1ffffff7f 0bc1 8945f4 8b55f4 }
            // n = 4, score = 200
            //   81e1ffffff7f         | and                 ecx, 0x7fffffff
            //   0bc1                 | or                  eax, ecx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 352256
}