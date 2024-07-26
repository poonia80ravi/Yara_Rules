rule win_dadjoke_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.dadjoke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dadjoke"
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
        $sequence_0 = { 56 57 6800081000 6a00 }
            // n = 4, score = 500
            //   56                   | push                esi
            //   57                   | push                edi
            //   6800081000           | push                0x100800
            //   6a00                 | push                0

        $sequence_1 = { 6a00 6a00 ff15???????? 6808020000 }
            // n = 4, score = 500
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6808020000           | push                0x208

        $sequence_2 = { 8b45fc 0fb68c1094010000 51 ba01000000 d1e2 8b45fc }
            // n = 6, score = 400
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fb68c1094010000     | movzx               ecx, byte ptr [eax + edx + 0x194]
            //   51                   | push                ecx
            //   ba01000000           | mov                 edx, 1
            //   d1e2                 | shl                 edx, 1
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_3 = { c745fcffffffff 8d4da4 e8???????? 8b4584 }
            // n = 4, score = 400
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   e8????????           |                     
            //   8b4584               | mov                 eax, dword ptr [ebp - 0x7c]

        $sequence_4 = { 8955d8 8b45d8 8945d4 837dd400 0f84ab000000 8b4d08 }
            // n = 6, score = 400
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   837dd400             | cmp                 dword ptr [ebp - 0x2c], 0
            //   0f84ab000000         | je                  0xb1
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_5 = { 7e0e b901000000 66890d???????? eb12 668b15???????? }
            // n = 5, score = 400
            //   7e0e                 | jle                 0x10
            //   b901000000           | mov                 ecx, 1
            //   66890d????????       |                     
            //   eb12                 | jmp                 0x14
            //   668b15????????       |                     

        $sequence_6 = { 8b0c82 0fb79104010000 52 83ec18 8bcc 8965c0 }
            // n = 6, score = 400
            //   8b0c82               | mov                 ecx, dword ptr [edx + eax*4]
            //   0fb79104010000       | movzx               edx, word ptr [ecx + 0x104]
            //   52                   | push                edx
            //   83ec18               | sub                 esp, 0x18
            //   8bcc                 | mov                 ecx, esp
            //   8965c0               | mov                 dword ptr [ebp - 0x40], esp

        $sequence_7 = { 51 8d4da4 e8???????? 8b55e0 8955d8 }
            // n = 5, score = 400
            //   51                   | push                ecx
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   e8????????           |                     
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx

        $sequence_8 = { e8???????? c3 6a04 e8???????? 59 c3 6a0c }
            // n = 7, score = 300
            //   e8????????           |                     
            //   c3                   | ret                 
            //   6a04                 | push                4
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   6a0c                 | push                0xc

        $sequence_9 = { 5e c3 8bff 55 8bec 83ec10 33c0 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { ff15???????? 85c0 7417 b920000000 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7417                 | je                  0x19
            //   b920000000           | mov                 ecx, 0x20

        $sequence_11 = { 84c0 0f94c1 8bc1 c3 a1???????? }
            // n = 5, score = 300
            //   84c0                 | test                al, al
            //   0f94c1               | sete                cl
            //   8bc1                 | mov                 eax, ecx
            //   c3                   | ret                 
            //   a1????????           |                     

        $sequence_12 = { ff15???????? 8bf0 8975f4 85f6 7431 6a00 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   85f6                 | test                esi, esi
            //   7431                 | je                  0x33
            //   6a00                 | push                0

        $sequence_13 = { 53 56 57 6a64 8d4590 c745f400000000 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a64                 | push                0x64
            //   8d4590               | lea                 eax, [ebp - 0x70]
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0

        $sequence_14 = { 56 57 6804010000 8d85f4fdffff 6a00 50 e8???????? }
            // n = 7, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   6804010000           | push                0x104
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_15 = { c7458c00000000 ff15???????? 50 e8???????? 83c404 bf3e000000 }
            // n = 6, score = 200
            //   c7458c00000000       | mov                 dword ptr [ebp - 0x74], 0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   bf3e000000           | mov                 edi, 0x3e

        $sequence_16 = { 6a00 680033a084 6a00 6a00 6a00 8d4590 50 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   680033a084           | push                0x84a03300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d4590               | lea                 eax, [ebp - 0x70]
            //   50                   | push                eax

        $sequence_17 = { 2bc6 7411 0f1f440000 0fbe4c15f4 42 03d9 }
            // n = 6, score = 200
            //   2bc6                 | sub                 eax, esi
            //   7411                 | je                  0x13
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   0fbe4c15f4           | movsx               ecx, byte ptr [ebp + edx - 0xc]
            //   42                   | inc                 edx
            //   03d9                 | add                 ebx, ecx

        $sequence_18 = { 8b85e0faffff 50 8b08 ff5108 8b85e4faffff 50 }
            // n = 6, score = 200
            //   8b85e0faffff         | mov                 eax, dword ptr [ebp - 0x520]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5108               | call                dword ptr [ecx + 8]
            //   8b85e4faffff         | mov                 eax, dword ptr [ebp - 0x51c]
            //   50                   | push                eax

        $sequence_19 = { 8b85e4faffff 50 8b08 ff5108 8b3d???????? 8b1d???????? }
            // n = 6, score = 200
            //   8b85e4faffff         | mov                 eax, dword ptr [ebp - 0x51c]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5108               | call                dword ptr [ecx + 8]
            //   8b3d????????         |                     
            //   8b1d????????         |                     

        $sequence_20 = { 8b4008 ffd0 8b55f8 83c604 8b4de4 }
            // n = 5, score = 100
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   ffd0                 | call                eax
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   83c604               | add                 esi, 4
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_21 = { 2b5834 85f6 744d 0fb74c5708 8bc1 c1e90c }
            // n = 6, score = 100
            //   2b5834               | sub                 ebx, dword ptr [eax + 0x34]
            //   85f6                 | test                esi, esi
            //   744d                 | je                  0x4f
            //   0fb74c5708           | movzx               ecx, word ptr [edi + edx*2 + 8]
            //   8bc1                 | mov                 eax, ecx
            //   c1e90c               | shr                 ecx, 0xc

    condition:
        7 of them and filesize < 344064
}