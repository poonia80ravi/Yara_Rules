rule win_moriagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.moriagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moriagent"
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
        $sequence_0 = { b802000000 eb05 b801000000 33ff }
            // n = 4, score = 200
            //   b802000000           | mov                 eax, 2
            //   eb05                 | jmp                 7
            //   b801000000           | mov                 eax, 1
            //   33ff                 | xor                 edi, edi

        $sequence_1 = { 0f43f2 3bf0 7437 8bf8 0f1f840000000000 0fbe06 50 }
            // n = 7, score = 100
            //   0f43f2               | cmovae              esi, edx
            //   3bf0                 | cmp                 esi, eax
            //   7437                 | je                  0x39
            //   8bf8                 | mov                 edi, eax
            //   0f1f840000000000     | nop                 dword ptr [eax + eax]
            //   0fbe06               | movsx               eax, byte ptr [esi]
            //   50                   | push                eax

        $sequence_2 = { b001 eb2c 7e04 32c0 eb26 }
            // n = 5, score = 100
            //   b001                 | mov                 al, 1
            //   eb2c                 | jmp                 0x2e
            //   7e04                 | jle                 6
            //   32c0                 | xor                 al, al
            //   eb26                 | jmp                 0x28

        $sequence_3 = { b09a 0000 00488b 0f4c8ba9800000 }
            // n = 4, score = 100
            //   b09a                 | cmove               eax, edx
            //   0000                 | mov                 byte ptr [esp + edx + 0x20], al
            //   00488b               | dec                 eax
            //   0f4c8ba9800000       | inc                 edx

        $sequence_4 = { b101 e8???????? 48894708 48897b40 }
            // n = 4, score = 100
            //   b101                 | jne                 0x22
            //   e8????????           |                     
            //   48894708             | nop                 dword ptr [eax + eax]
            //   48897b40             | test                cl, cl

        $sequence_5 = { b130 80f939 7f1c 49898080000000 }
            // n = 4, score = 100
            //   b130                 | dec                 eax
            //   80f939               | mov                 ebx, dword ptr [esp + 0x40]
            //   7f1c                 | mov                 cl, 1
            //   49898080000000       | dec                 eax

        $sequence_6 = { 51 e8???????? 8b7524 b8abaaaa2a 8b4d2c 83c404 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b7524               | mov                 esi, dword ptr [ebp + 0x24]
            //   b8abaaaa2a           | mov                 eax, 0x2aaaaaab
            //   8b4d2c               | mov                 ecx, dword ptr [ebp + 0x2c]
            //   83c404               | add                 esp, 4

        $sequence_7 = { 83e001 0f840c000000 8365f0fe 8b4dc8 e9???????? c3 }
            // n = 6, score = 100
            //   83e001               | and                 eax, 1
            //   0f840c000000         | je                  0x12
            //   8365f0fe             | and                 dword ptr [ebp - 0x10], 0xfffffffe
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]
            //   e9????????           |                     
            //   c3                   | ret                 

        $sequence_8 = { 0d80000000 83c808 c745fc0c000000 8db524efffff }
            // n = 4, score = 100
            //   0d80000000           | or                  eax, 0x80
            //   83c808               | or                  eax, 8
            //   c745fc0c000000       | mov                 dword ptr [ebp - 4], 0xc
            //   8db524efffff         | lea                 esi, [ebp - 0x10dc]

        $sequence_9 = { b101 83f80f 7520 0f1f440000 }
            // n = 4, score = 100
            //   b101                 | cmovl               ecx, dword ptr [ebx + 0x80a9]
            //   83f80f               | add                 byte ptr [ecx + ecx*4 + 0x6d], cl
            //   7520                 | scasd               eax, dword ptr es:[edi]
            //   0f1f440000           | inc                 ebp

        $sequence_10 = { b03e eb0c 80f92f b8ff000000 }
            // n = 4, score = 100
            //   b03e                 | mov                 al, 0x3e
            //   eb0c                 | jmp                 0xe
            //   80f92f               | cmp                 cl, 0x2f
            //   b8ff000000           | mov                 eax, 0xff

        $sequence_11 = { 46 52 ef 6e 86f2 fd }
            // n = 6, score = 100
            //   46                   | inc                 esi
            //   52                   | push                edx
            //   ef                   | out                 dx, eax
            //   6e                   | outsb               dx, byte ptr [esi]
            //   86f2                 | xchg                dl, dh
            //   fd                   | std                 

        $sequence_12 = { e8???????? 83c408 8b45f0 03c7 893b 894304 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   03c7                 | add                 eax, edi
            //   893b                 | mov                 dword ptr [ebx], edi
            //   894304               | mov                 dword ptr [ebx + 4], eax

        $sequence_13 = { 8b85e8eeffff 83c408 c78594efffff00000000 c78598efffff0f000000 c68584efffff00 c745fc0c000000 }
            // n = 6, score = 100
            //   8b85e8eeffff         | mov                 eax, dword ptr [ebp - 0x1118]
            //   83c408               | add                 esp, 8
            //   c78594efffff00000000     | mov    dword ptr [ebp - 0x106c], 0
            //   c78598efffff0f000000     | mov    dword ptr [ebp - 0x1068], 0xf
            //   c68584efffff00       | mov                 byte ptr [ebp - 0x107c], 0
            //   c745fc0c000000       | mov                 dword ptr [ebp - 4], 0xc

        $sequence_14 = { b201 488bcb e8???????? 88442430 488b03 }
            // n = 5, score = 100
            //   b201                 | dec                 eax
            //   488bcb               | mov                 dword ptr [ebx + 0x60], edi
            //   e8????????           |                     
            //   88442430             | dec                 eax
            //   488b03               | lea                 eax, [ebx + 8]

    condition:
        7 of them and filesize < 1347904
}