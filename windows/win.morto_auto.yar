rule win_morto_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.morto."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.morto"
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
        $sequence_0 = { 42 46 4f 75f6 89542410 e9???????? }
            // n = 6, score = 200
            //   42                   | inc                 edx
            //   46                   | inc                 esi
            //   4f                   | dec                 edi
            //   75f6                 | jne                 0xfffffff8
            //   89542410             | mov                 dword ptr [esp + 0x10], edx
            //   e9????????           |                     

        $sequence_1 = { eb11 3c61 7c40 3c7a 7f3c 0fbec0 }
            // n = 6, score = 200
            //   eb11                 | jmp                 0x13
            //   3c61                 | cmp                 al, 0x61
            //   7c40                 | jl                  0x42
            //   3c7a                 | cmp                 al, 0x7a
            //   7f3c                 | jg                  0x3e
            //   0fbec0               | movsx               eax, al

        $sequence_2 = { 03fa 8b542410 8bf2 2bf5 8b6c2424 }
            // n = 5, score = 200
            //   03fa                 | add                 edi, edx
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   8bf2                 | mov                 esi, edx
            //   2bf5                 | sub                 esi, ebp
            //   8b6c2424             | mov                 ebp, dword ptr [esp + 0x24]

        $sequence_3 = { 8945fc 03d0 833a00 744c 8b7d08 8d4a04 }
            // n = 6, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   03d0                 | add                 edx, eax
            //   833a00               | cmp                 dword ptr [edx], 0
            //   744c                 | je                  0x4e
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d4a04               | lea                 ecx, [edx + 4]

        $sequence_4 = { e8???????? 3bc3 741b 53 68???????? ff750c }
            // n = 6, score = 200
            //   e8????????           |                     
            //   3bc3                 | cmp                 eax, ebx
            //   741b                 | je                  0x1d
            //   53                   | push                ebx
            //   68????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_5 = { 8b470c 8bb080000000 037704 bb04030201 391e 0f8594000000 83c604 }
            // n = 7, score = 200
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   8bb080000000         | mov                 esi, dword ptr [eax + 0x80]
            //   037704               | add                 esi, dword ptr [edi + 4]
            //   bb04030201           | mov                 ebx, 0x1020304
            //   391e                 | cmp                 dword ptr [esi], ebx
            //   0f8594000000         | jne                 0x9a
            //   83c604               | add                 esi, 4

        $sequence_6 = { 0fb75601 6a07 5b eb11 8bfe 83c9ff }
            // n = 6, score = 200
            //   0fb75601             | movzx               edx, word ptr [esi + 1]
            //   6a07                 | push                7
            //   5b                   | pop                 ebx
            //   eb11                 | jmp                 0x13
            //   8bfe                 | mov                 edi, esi
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_7 = { 8b5020 8b701c 8b4018 03cb 03d3 03f3 8945f0 }
            // n = 7, score = 200
            //   8b5020               | mov                 edx, dword ptr [eax + 0x20]
            //   8b701c               | mov                 esi, dword ptr [eax + 0x1c]
            //   8b4018               | mov                 eax, dword ptr [eax + 0x18]
            //   03cb                 | add                 ecx, ebx
            //   03d3                 | add                 edx, ebx
            //   03f3                 | add                 esi, ebx
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_8 = { 55 33c9 56 57 33c0 }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   33c9                 | xor                 ecx, ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 8b4604 8b4f04 03c1 6a01 89470c }
            // n = 5, score = 200
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   8b4f04               | mov                 ecx, dword ptr [edi + 4]
            //   03c1                 | add                 eax, ecx
            //   6a01                 | push                1
            //   89470c               | mov                 dword ptr [edi + 0xc], eax

    condition:
        7 of them and filesize < 49152
}