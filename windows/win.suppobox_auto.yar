rule win_suppobox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.suppobox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.suppobox"
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
        $sequence_0 = { 7f10 a1???????? 2305???????? a3???????? }
            // n = 4, score = 200
            //   7f10                 | jg                  0x12
            //   a1????????           |                     
            //   2305????????         |                     
            //   a3????????           |                     

        $sequence_1 = { 7e10 a1???????? 0305???????? a3???????? }
            // n = 4, score = 200
            //   7e10                 | jle                 0x12
            //   a1????????           |                     
            //   0305????????         |                     
            //   a3????????           |                     

        $sequence_2 = { 8945f0 a1???????? 83e801 a3???????? }
            // n = 4, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   a1????????           |                     
            //   83e801               | sub                 eax, 1
            //   a3????????           |                     

        $sequence_3 = { 7412 8b0d???????? 030d???????? 890d???????? }
            // n = 4, score = 200
            //   7412                 | je                  0x14
            //   8b0d????????         |                     
            //   030d????????         |                     
            //   890d????????         |                     

        $sequence_4 = { 890d???????? e8???????? 8bf0 e8???????? 03f0 }
            // n = 5, score = 200
            //   890d????????         |                     
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   03f0                 | add                 esi, eax

        $sequence_5 = { 7d10 a1???????? 3305???????? a3???????? }
            // n = 4, score = 200
            //   7d10                 | jge                 0x12
            //   a1????????           |                     
            //   3305????????         |                     
            //   a3????????           |                     

        $sequence_6 = { 3bc8 7d10 a1???????? 2b05???????? a3???????? }
            // n = 5, score = 200
            //   3bc8                 | cmp                 ecx, eax
            //   7d10                 | jge                 0x12
            //   a1????????           |                     
            //   2b05????????         |                     
            //   a3????????           |                     

        $sequence_7 = { 01bdacf7ffff 83c40c 83bdc8f7ffff00 8b95c8f7ffff }
            // n = 4, score = 100
            //   01bdacf7ffff         | add                 dword ptr [ebp - 0x854], edi
            //   83c40c               | add                 esp, 0xc
            //   83bdc8f7ffff00       | cmp                 dword ptr [ebp - 0x838], 0
            //   8b95c8f7ffff         | mov                 edx, dword ptr [ebp - 0x838]

        $sequence_8 = { 01c6 ebdb ff7510 57 }
            // n = 4, score = 100
            //   01c6                 | add                 esi, eax
            //   ebdb                 | jmp                 0xffffffdd
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   57                   | push                edi

        $sequence_9 = { 8b9300010000 81faff000000 744e 8d4201 898300010000 }
            // n = 5, score = 100
            //   8b9300010000         | mov                 edx, dword ptr [ebx + 0x100]
            //   81faff000000         | cmp                 edx, 0xff
            //   744e                 | je                  0x50
            //   8d4201               | lea                 eax, [edx + 1]
            //   898300010000         | mov                 dword ptr [ebx + 0x100], eax

        $sequence_10 = { 8b9318010000 85d2 0f84cd000000 80bb040100003c }
            // n = 4, score = 100
            //   8b9318010000         | mov                 edx, dword ptr [ebx + 0x118]
            //   85d2                 | test                edx, edx
            //   0f84cd000000         | je                  0xd3
            //   80bb040100003c       | cmp                 byte ptr [ebx + 0x104], 0x3c

        $sequence_11 = { 01c6 39fe 0f8d7e010000 80bc2ef4f7ffff0a }
            // n = 4, score = 100
            //   01c6                 | add                 esi, eax
            //   39fe                 | cmp                 esi, edi
            //   0f8d7e010000         | jge                 0x184
            //   80bc2ef4f7ffff0a     | cmp                 byte ptr [esi + ebp - 0x80c], 0xa

        $sequence_12 = { 8b930c010000 c6040300 89442404 891c24 }
            // n = 4, score = 100
            //   8b930c010000         | mov                 edx, dword ptr [ebx + 0x10c]
            //   c6040300             | mov                 byte ptr [ebx + eax], 0
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   891c24               | mov                 dword ptr [esp], ebx

        $sequence_13 = { 01d8 3b85b0f7ffff 7e2f 8b95c8f7ffff }
            // n = 4, score = 100
            //   01d8                 | add                 eax, ebx
            //   3b85b0f7ffff         | cmp                 eax, dword ptr [ebp - 0x850]
            //   7e2f                 | jle                 0x31
            //   8b95c8f7ffff         | mov                 edx, dword ptr [ebp - 0x838]

        $sequence_14 = { 8b9300010000 81faff000000 7478 8d4a01 }
            // n = 4, score = 100
            //   8b9300010000         | mov                 edx, dword ptr [ebx + 0x100]
            //   81faff000000         | cmp                 edx, 0xff
            //   7478                 | je                  0x7a
            //   8d4a01               | lea                 ecx, [edx + 1]

        $sequence_15 = { 01c9 4a 79f2 833b54 }
            // n = 4, score = 100
            //   01c9                 | add                 ecx, ecx
            //   4a                   | dec                 edx
            //   79f2                 | jns                 0xfffffff4
            //   833b54               | cmp                 dword ptr [ebx], 0x54

        $sequence_16 = { 01d7 68???????? 57 e8???????? }
            // n = 4, score = 100
            //   01d7                 | add                 edi, edx
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_17 = { 8b930c010000 8944240c c683ff00000000 c7442404ff000000 }
            // n = 4, score = 100
            //   8b930c010000         | mov                 edx, dword ptr [ebx + 0x10c]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   c683ff00000000       | mov                 byte ptr [ebx + 0xff], 0
            //   c7442404ff000000     | mov                 dword ptr [esp + 4], 0xff

        $sequence_18 = { 8b9318010000 85d2 743d 3dff000000 }
            // n = 4, score = 100
            //   8b9318010000         | mov                 edx, dword ptr [ebx + 0x118]
            //   85d2                 | test                edx, edx
            //   743d                 | je                  0x3f
            //   3dff000000           | cmp                 eax, 0xff

        $sequence_19 = { 8b9318010000 85d2 743b 3dff000000 }
            // n = 4, score = 100
            //   8b9318010000         | mov                 edx, dword ptr [ebx + 0x118]
            //   85d2                 | test                edx, edx
            //   743b                 | je                  0x3d
            //   3dff000000           | cmp                 eax, 0xff

        $sequence_20 = { 01c6 39fe 0f8d2f020000 80bc2ef4f7ffff0a }
            // n = 4, score = 100
            //   01c6                 | add                 esi, eax
            //   39fe                 | cmp                 esi, edi
            //   0f8d2f020000         | jge                 0x235
            //   80bc2ef4f7ffff0a     | cmp                 byte ptr [esi + ebp - 0x80c], 0xa

        $sequence_21 = { 019dacf7ffff 83c40c 299dc4f7ffff e9???????? }
            // n = 4, score = 100
            //   019dacf7ffff         | add                 dword ptr [ebp - 0x854], ebx
            //   83c40c               | add                 esp, 0xc
            //   299dc4f7ffff         | sub                 dword ptr [ebp - 0x83c], ebx
            //   e9????????           |                     

    condition:
        7 of them and filesize < 1875968
}