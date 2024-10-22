rule win_linseningsvr_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.linseningsvr."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.linseningsvr"
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
        $sequence_0 = { 751a 68???????? e8???????? 83c404 33c0 5f 5e }
            // n = 7, score = 100
            //   751a                 | jne                 0x1c
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_1 = { 8b0485c08d4000 8d04c8 8b0b 8908 8a4d00 }
            // n = 5, score = 100
            //   8b0485c08d4000       | mov                 eax, dword ptr [eax*4 + 0x408dc0]
            //   8d04c8               | lea                 eax, [eax + ecx*8]
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8a4d00               | mov                 cl, byte ptr [ebp]

        $sequence_2 = { 8d542464 6a01 52 89442464 894c2468 }
            // n = 5, score = 100
            //   8d542464             | lea                 edx, [esp + 0x64]
            //   6a01                 | push                1
            //   52                   | push                edx
            //   89442464             | mov                 dword ptr [esp + 0x64], eax
            //   894c2468             | mov                 dword ptr [esp + 0x68], ecx

        $sequence_3 = { c1f805 83e61f 8d1c85c08d4000 c1e603 8b03 f644300401 7469 }
            // n = 7, score = 100
            //   c1f805               | sar                 eax, 5
            //   83e61f               | and                 esi, 0x1f
            //   8d1c85c08d4000       | lea                 ebx, [eax*4 + 0x408dc0]
            //   c1e603               | shl                 esi, 3
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   f644300401           | test                byte ptr [eax + esi + 4], 1
            //   7469                 | je                  0x6b

        $sequence_4 = { e8???????? b900010000 33c0 8dbc2450040000 55 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   b900010000           | mov                 ecx, 0x100
            //   33c0                 | xor                 eax, eax
            //   8dbc2450040000       | lea                 edi, [esp + 0x450]
            //   55                   | push                ebp

        $sequence_5 = { 8bd0 c1f905 83e21f 8b0c8dc08d4000 }
            // n = 4, score = 100
            //   8bd0                 | mov                 edx, eax
            //   c1f905               | sar                 ecx, 5
            //   83e21f               | and                 edx, 0x1f
            //   8b0c8dc08d4000       | mov                 ecx, dword ptr [ecx*4 + 0x408dc0]

        $sequence_6 = { 7415 e8???????? 5f 5e 5d b801000000 5b }
            // n = 7, score = 100
            //   7415                 | je                  0x17
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx

        $sequence_7 = { 8a4c3c4c 51 68???????? e8???????? 83c408 47 }
            // n = 6, score = 100
            //   8a4c3c4c             | mov                 cl, byte ptr [esp + edi + 0x4c]
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   47                   | inc                 edi

        $sequence_8 = { 83c42c 5f eb26 8d4508 8db6fc874000 6a00 50 }
            // n = 7, score = 100
            //   83c42c               | add                 esp, 0x2c
            //   5f                   | pop                 edi
            //   eb26                 | jmp                 0x28
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8db6fc874000         | lea                 esi, [esi + 0x4087fc]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_9 = { 3b96f8874000 0f851c010000 a1???????? 83f801 }
            // n = 4, score = 100
            //   3b96f8874000         | cmp                 edx, dword ptr [esi + 0x4087f8]
            //   0f851c010000         | jne                 0x122
            //   a1????????           |                     
            //   83f801               | cmp                 eax, 1

    condition:
        7 of them and filesize < 81360
}