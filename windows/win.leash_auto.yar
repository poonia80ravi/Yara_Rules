rule win_leash_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.leash."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.leash"
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
        $sequence_0 = { 83c404 85c0 75e2 8b542414 8a84141c100000 84c0 0f85b5feffff }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   75e2                 | jne                 0xffffffe4
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8a84141c100000       | mov                 al, byte ptr [esp + edx + 0x101c]
            //   84c0                 | test                al, al
            //   0f85b5feffff         | jne                 0xfffffebb

        $sequence_1 = { c68424fc25000000 f3ab 66ab aa b9ff000000 33c0 8dbc24fd250000 }
            // n = 7, score = 200
            //   c68424fc25000000     | mov                 byte ptr [esp + 0x25fc], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b9ff000000           | mov                 ecx, 0xff
            //   33c0                 | xor                 eax, eax
            //   8dbc24fd250000       | lea                 edi, [esp + 0x25fd]

        $sequence_2 = { 8bfb 8b9c2424200000 c1e902 f3a5 8bc8 88542413 83e103 }
            // n = 7, score = 200
            //   8bfb                 | mov                 edi, ebx
            //   8b9c2424200000       | mov                 ebx, dword ptr [esp + 0x2024]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   88542413             | mov                 byte ptr [esp + 0x13], dl
            //   83e103               | and                 ecx, 3

        $sequence_3 = { 8b54b304 8b442428 52 50 e8???????? ddd8 83c40c }
            // n = 7, score = 200
            //   8b54b304             | mov                 edx, dword ptr [ebx + esi*4 + 4]
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   ddd8                 | fstp                st(0)
            //   83c40c               | add                 esp, 0xc

        $sequence_4 = { 74f7 8b0d???????? 894c2410 c784240452000003000000 }
            // n = 4, score = 200
            //   74f7                 | je                  0xfffffff9
            //   8b0d????????         |                     
            //   894c2410             | mov                 dword ptr [esp + 0x10], ecx
            //   c784240452000003000000     | mov    dword ptr [esp + 0x5204], 3

        $sequence_5 = { 7417 8dbda0feffff 83c9ff 33c0 f2ae f7d1 49 }
            // n = 7, score = 200
            //   7417                 | je                  0x19
            //   8dbda0feffff         | lea                 edi, [ebp - 0x160]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx

        $sequence_6 = { 85c0 7423 8b4de8 8b550c 51 8b0d???????? 8d85a0fbffff }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7423                 | je                  0x25
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   8b0d????????         |                     
            //   8d85a0fbffff         | lea                 eax, [ebp - 0x460]

        $sequence_7 = { 8d8f0c040000 e8???????? eb5c 6a20 56 }
            // n = 5, score = 200
            //   8d8f0c040000         | lea                 ecx, [edi + 0x40c]
            //   e8????????           |                     
            //   eb5c                 | jmp                 0x5e
            //   6a20                 | push                0x20
            //   56                   | push                esi

        $sequence_8 = { 8b7d20 8bf0 8bc1 c1e902 f3a5 8bc8 83e103 }
            // n = 7, score = 200
            //   8b7d20               | mov                 edi, dword ptr [ebp + 0x20]
            //   8bf0                 | mov                 esi, eax
            //   8bc1                 | mov                 eax, ecx
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3

        $sequence_9 = { 3bf0 7ee9 8b450c 50 e8???????? 83c404 8b4510 }
            // n = 7, score = 200
            //   3bf0                 | cmp                 esi, eax
            //   7ee9                 | jle                 0xffffffeb
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

    condition:
        7 of them and filesize < 761856
}