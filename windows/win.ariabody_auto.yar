rule win_ariabody_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ariabody."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ariabody"
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
        $sequence_0 = { 3ac3 7402 32c3 88040a }
            // n = 4, score = 300
            //   3ac3                 | cmp                 al, bl
            //   7402                 | je                  4
            //   32c3                 | xor                 al, bl
            //   88040a               | mov                 byte ptr [edx + ecx], al

        $sequence_1 = { 50 ff75fc e8???????? 83c40c 85db }
            // n = 5, score = 300
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85db                 | test                ebx, ebx

        $sequence_2 = { 8bd9 e8???????? 8bf8 893b }
            // n = 4, score = 300
            //   8bd9                 | mov                 ebx, ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   893b                 | mov                 dword ptr [ebx], edi

        $sequence_3 = { ff5304 8bf8 893e eb13 8b16 8bcf }
            // n = 6, score = 300
            //   ff5304               | call                dword ptr [ebx + 4]
            //   8bf8                 | mov                 edi, eax
            //   893e                 | mov                 dword ptr [esi], edi
            //   eb13                 | jmp                 0x15
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8bcf                 | mov                 ecx, edi

        $sequence_4 = { 8a01 84c0 7406 3ac3 7402 }
            // n = 5, score = 300
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   84c0                 | test                al, al
            //   7406                 | je                  8
            //   3ac3                 | cmp                 al, bl
            //   7402                 | je                  4

        $sequence_5 = { 8bec 83ec50 53 57 8bd9 e8???????? }
            // n = 6, score = 300
            //   8bec                 | mov                 ebp, esp
            //   83ec50               | sub                 esp, 0x50
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8bd9                 | mov                 ebx, ecx
            //   e8????????           |                     

        $sequence_6 = { 8d0c30 ffd1 8bc6 5f }
            // n = 4, score = 300
            //   8d0c30               | lea                 ecx, [eax + esi]
            //   ffd1                 | call                ecx
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi

        $sequence_7 = { 8bf2 56 8d55fc 03f9 e8???????? 59 }
            // n = 6, score = 300
            //   8bf2                 | mov                 esi, edx
            //   56                   | push                esi
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   03f9                 | add                 edi, ecx
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_8 = { 33d2 4d8d8708030000 41b9ffffffff 488d442430 }
            // n = 4, score = 100
            //   33d2                 | inc                 sp
            //   4d8d8708030000       | mov                 dword ptr [esp + 0x198], edx
            //   41b9ffffffff         | call                dword ptr [esi + 0x50]
            //   488d442430           | xor                 edx, edx

        $sequence_9 = { f7e1 41ffc3 c1ea07 89d0 }
            // n = 4, score = 100
            //   f7e1                 | dec                 esp
            //   41ffc3               | mov                 esi, dword ptr [esp + 0x28]
            //   c1ea07               | inc                 sp
            //   89d0                 | mov                 dword ptr [esp + 0x18e], ecx

        $sequence_10 = { 4883c508 48837d0000 75dd c744246061647661 488d4c2460 }
            // n = 5, score = 100
            //   4883c508             | dec                 eax
            //   48837d0000           | lea                 edi, [esp + 0x30]
            //   75dd                 | mul                 ecx
            //   c744246061647661     | inc                 ecx
            //   488d4c2460           | inc                 ebx

        $sequence_11 = { 488d05bd040100 483bc8 772b 0fba71180f }
            // n = 4, score = 100
            //   488d05bd040100       | shr                 edx, 7
            //   483bc8               | mov                 eax, edx
            //   772b                 | xor                 edx, edx
            //   0fba71180f           | dec                 ebp

        $sequence_12 = { 33c0 488b742448 488b7c2450 4c8b642458 4c8b6c2420 4c8b742428 }
            // n = 6, score = 100
            //   33c0                 | dec                 eax
            //   488b742448           | mov                 ecx, ebx
            //   488b7c2450           | xor                 eax, eax
            //   4c8b642458           | dec                 eax
            //   4c8b6c2420           | mov                 esi, dword ptr [esp + 0x48]
            //   4c8b742428           | dec                 eax

        $sequence_13 = { 6644898c248e010000 664489942498010000 ff5650 33d2 488d7c2430 }
            // n = 5, score = 100
            //   6644898c248e010000     | mov    edi, dword ptr [esp + 0x50]
            //   664489942498010000     | dec    esp
            //   ff5650               | mov                 esp, dword ptr [esp + 0x58]
            //   33d2                 | dec                 esp
            //   488d7c2430           | mov                 ebp, dword ptr [esp + 0x20]

        $sequence_14 = { ff15???????? 488d15b9780000 483305???????? 488bcb 488905???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488d15b9780000       | dec                 eax
            //   483305????????       |                     
            //   488bcb               | lea                 edx, [0x78b9]
            //   488905????????       |                     

        $sequence_15 = { ff15???????? cc 4c8d05e3feffff 4533c9 33d2 33c9 48895c2428 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   cc                   | lea                 eax, [edi + 0x308]
            //   4c8d05e3feffff       | inc                 ecx
            //   4533c9               | mov                 ecx, 0xffffffff
            //   33d2                 | dec                 eax
            //   33c9                 | lea                 eax, [esp + 0x30]
            //   48895c2428           | dec                 eax

    condition:
        7 of them and filesize < 253952
}