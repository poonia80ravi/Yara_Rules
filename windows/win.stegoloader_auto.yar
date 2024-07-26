rule win_stegoloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.stegoloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stegoloader"
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
        $sequence_0 = { 83c604 85c0 7603 8d34c6 }
            // n = 4, score = 200
            //   83c604               | add                 esi, 4
            //   85c0                 | test                eax, eax
            //   7603                 | jbe                 5
            //   8d34c6               | lea                 esi, [esi + eax*8]

        $sequence_1 = { 803c022e 75f9 56 8d740201 33ff 803e00 }
            // n = 6, score = 200
            //   803c022e             | cmp                 byte ptr [edx + eax], 0x2e
            //   75f9                 | jne                 0xfffffffb
            //   56                   | push                esi
            //   8d740201             | lea                 esi, [edx + eax + 1]
            //   33ff                 | xor                 edi, edi
            //   803e00               | cmp                 byte ptr [esi], 0

        $sequence_2 = { 59 7423 e8???????? 84c0 }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   7423                 | je                  0x25
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_3 = { 720e 8b4df0 03ce 3bc1 }
            // n = 4, score = 200
            //   720e                 | jb                  0x10
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   03ce                 | add                 ecx, esi
            //   3bc1                 | cmp                 eax, ecx

        $sequence_4 = { 59 59 7440 ff45f8 8b45f8 83c304 3b4618 }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   7440                 | je                  0x42
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c304               | add                 ebx, 4
            //   3b4618               | cmp                 eax, dword ptr [esi + 0x18]

        $sequence_5 = { 8d0448 0fb70438 eb07 662b5e10 0fb7c3 8b4e1c }
            // n = 6, score = 200
            //   8d0448               | lea                 eax, [eax + ecx*2]
            //   0fb70438             | movzx               eax, word ptr [eax + edi]
            //   eb07                 | jmp                 9
            //   662b5e10             | sub                 bx, word ptr [esi + 0x10]
            //   0fb7c3               | movzx               eax, bx
            //   8b4e1c               | mov                 ecx, dword ptr [esi + 0x1c]

        $sequence_6 = { 6a01 8bce ff5004 eb07 8b4508 8930 }
            // n = 6, score = 200
            //   6a01                 | push                1
            //   8bce                 | mov                 ecx, esi
            //   ff5004               | call                dword ptr [eax + 4]
            //   eb07                 | jmp                 9
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8930                 | mov                 dword ptr [eax], esi

        $sequence_7 = { c645d753 c645d854 c645d945 c645da4d c645db49 }
            // n = 5, score = 200
            //   c645d753             | mov                 byte ptr [ebp - 0x29], 0x53
            //   c645d854             | mov                 byte ptr [ebp - 0x28], 0x54
            //   c645d945             | mov                 byte ptr [ebp - 0x27], 0x45
            //   c645da4d             | mov                 byte ptr [ebp - 0x26], 0x4d
            //   c645db49             | mov                 byte ptr [ebp - 0x25], 0x49

        $sequence_8 = { 8b55fc 8d043e 8a0408 880411 41 3b4df8 }
            // n = 6, score = 200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8d043e               | lea                 eax, [esi + edi]
            //   8a0408               | mov                 al, byte ptr [eax + ecx]
            //   880411               | mov                 byte ptr [ecx + edx], al
            //   41                   | inc                 ecx
            //   3b4df8               | cmp                 ecx, dword ptr [ebp - 8]

        $sequence_9 = { 7449 57 6a14 e8???????? }
            // n = 4, score = 200
            //   7449                 | je                  0x4b
            //   57                   | push                edi
            //   6a14                 | push                0x14
            //   e8????????           |                     

        $sequence_10 = { 8b44240c 0fb60c02 6a08 5e }
            // n = 4, score = 200
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   0fb60c02             | movzx               ecx, byte ptr [edx + eax]
            //   6a08                 | push                8
            //   5e                   | pop                 esi

        $sequence_11 = { 885dfc e8???????? 84c0 7434 6a05 }
            // n = 5, score = 200
            //   885dfc               | mov                 byte ptr [ebp - 4], bl
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7434                 | je                  0x36
            //   6a05                 | push                5

        $sequence_12 = { 56 57 ff15???????? 85c0 742b 8b4510 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742b                 | je                  0x2d
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_13 = { 753c 394e18 894df8 7657 8b5e20 03df }
            // n = 6, score = 200
            //   753c                 | jne                 0x3e
            //   394e18               | cmp                 dword ptr [esi + 0x18], ecx
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   7657                 | jbe                 0x59
            //   8b5e20               | mov                 ebx, dword ptr [esi + 0x20]
            //   03df                 | add                 ebx, edi

        $sequence_14 = { 25ffffff7f 33d2 80382e 7407 42 }
            // n = 5, score = 200
            //   25ffffff7f           | and                 eax, 0x7fffffff
            //   33d2                 | xor                 edx, edx
            //   80382e               | cmp                 byte ptr [eax], 0x2e
            //   7407                 | je                  9
            //   42                   | inc                 edx

        $sequence_15 = { 59 750d ff7508 e8???????? 84c0 }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   750d                 | jne                 0xf
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   84c0                 | test                al, al

    condition:
        7 of them and filesize < 802816
}