rule win_powersniff_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.powersniff."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powersniff"
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
        $sequence_0 = { c1e608 c1eb08 0fb6fb 3334bd90740010 0fb67df8 8b5df4 }
            // n = 6, score = 100
            //   c1e608               | shl                 esi, 8
            //   c1eb08               | shr                 ebx, 8
            //   0fb6fb               | movzx               edi, bl
            //   3334bd90740010       | xor                 esi, dword ptr [edi*4 + 0x10007490]
            //   0fb67df8             | movzx               edi, byte ptr [ebp - 8]
            //   8b5df4               | mov                 ebx, dword ptr [ebp - 0xc]

        $sequence_1 = { 897df8 3bfb 7416 53 8d45f4 50 57 }
            // n = 7, score = 100
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   3bfb                 | cmp                 edi, ebx
            //   7416                 | je                  0x18
            //   53                   | push                ebx
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_2 = { 8918 5b c9 c20800 55 8bec 83ec0c }
            // n = 7, score = 100
            //   8918                 | mov                 dword ptr [eax], ebx
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc

        $sequence_3 = { 33f6 50 e8???????? 85c0 750c }
            // n = 5, score = 100
            //   33f6                 | xor                 esi, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe

        $sequence_4 = { 5b ff75f8 ff15???????? 8b45fc c9 c3 8b442408 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c9                   | leave               
            //   c3                   | ret                 
            //   8b442408             | mov                 eax, dword ptr [esp + 8]

        $sequence_5 = { 57 6a1f 8d45dc 50 57 c745fcae020000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   6a1f                 | push                0x1f
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   57                   | push                edi
            //   c745fcae020000       | mov                 dword ptr [ebp - 4], 0x2ae

        $sequence_6 = { c1e608 897508 3334bd90740010 c1eb10 337004 0fb6fb 8b5df0 }
            // n = 7, score = 100
            //   c1e608               | shl                 esi, 8
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   3334bd90740010       | xor                 esi, dword ptr [edi*4 + 0x10007490]
            //   c1eb10               | shr                 ebx, 0x10
            //   337004               | xor                 esi, dword ptr [eax + 4]
            //   0fb6fb               | movzx               edi, bl
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]

        $sequence_7 = { 8bcb 33349590800010 0fb655f0 33349590840010 c1e908 33700c 03c7 }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   33349590800010       | xor                 esi, dword ptr [edx*4 + 0x10008090]
            //   0fb655f0             | movzx               edx, byte ptr [ebp - 0x10]
            //   33349590840010       | xor                 esi, dword ptr [edx*4 + 0x10008490]
            //   c1e908               | shr                 ecx, 8
            //   33700c               | xor                 esi, dword ptr [eax + 0xc]
            //   03c7                 | add                 eax, edi

        $sequence_8 = { 0fb65df4 8975e8 8b75f0 c1ee18 8b34b590780010 3175e8 8b75e8 }
            // n = 7, score = 100
            //   0fb65df4             | movzx               ebx, byte ptr [ebp - 0xc]
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   8b75f0               | mov                 esi, dword ptr [ebp - 0x10]
            //   c1ee18               | shr                 esi, 0x18
            //   8b34b590780010       | mov                 esi, dword ptr [esi*4 + 0x10007890]
            //   3175e8               | xor                 dword ptr [ebp - 0x18], esi
            //   8b75e8               | mov                 esi, dword ptr [ebp - 0x18]

        $sequence_9 = { 0fb6f3 8b5d08 331cb590800010 0fb6f2 }
            // n = 4, score = 100
            //   0fb6f3               | movzx               esi, bl
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   331cb590800010       | xor                 ebx, dword ptr [esi*4 + 0x10008090]
            //   0fb6f2               | movzx               esi, dl

    condition:
        7 of them and filesize < 90112
}