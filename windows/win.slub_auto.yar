rule win_slub_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.slub."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slub"
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
        $sequence_0 = { 89842438010000 8b842444010000 53 55 56 57 8bbc2450010000 }
            // n = 7, score = 100
            //   89842438010000       | mov                 dword ptr [esp + 0x138], eax
            //   8b842444010000       | mov                 eax, dword ptr [esp + 0x144]
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bbc2450010000       | mov                 edi, dword ptr [esp + 0x150]

        $sequence_1 = { eb05 1bc0 83c801 85c0 7412 e9???????? 83be7003000000 }
            // n = 7, score = 100
            //   eb05                 | jmp                 7
            //   1bc0                 | sbb                 eax, eax
            //   83c801               | or                  eax, 1
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14
            //   e9????????           |                     
            //   83be7003000000       | cmp                 dword ptr [esi + 0x370], 0

        $sequence_2 = { c785d8ebffff00000000 c685c8ebffff00 83f808 7213 40 8d8db0ebffff 50 }
            // n = 7, score = 100
            //   c785d8ebffff00000000     | mov    dword ptr [ebp - 0x1428], 0
            //   c685c8ebffff00       | mov                 byte ptr [ebp - 0x1438], 0
            //   83f808               | cmp                 eax, 8
            //   7213                 | jb                  0x15
            //   40                   | inc                 eax
            //   8d8db0ebffff         | lea                 ecx, [ebp - 0x1450]
            //   50                   | push                eax

        $sequence_3 = { 84d2 7562 81bef80000002c010000 0f8db0000000 389ea0090000 0f85a4000000 389f92020000 }
            // n = 7, score = 100
            //   84d2                 | test                dl, dl
            //   7562                 | jne                 0x64
            //   81bef80000002c010000     | cmp    dword ptr [esi + 0xf8], 0x12c
            //   0f8db0000000         | jge                 0xb6
            //   389ea0090000         | cmp                 byte ptr [esi + 0x9a0], bl
            //   0f85a4000000         | jne                 0xaa
            //   389f92020000         | cmp                 byte ptr [edi + 0x292], bl

        $sequence_4 = { ffb7b0060000 ff15???????? 83c404 c687b406000000 c787b006000000000000 8d8760020000 5f }
            // n = 7, score = 100
            //   ffb7b0060000         | push                dword ptr [edi + 0x6b0]
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   c687b406000000       | mov                 byte ptr [edi + 0x6b4], 0
            //   c787b006000000000000     | mov    dword ptr [edi + 0x6b0], 0
            //   8d8760020000         | lea                 eax, [edi + 0x260]
            //   5f                   | pop                 edi

        $sequence_5 = { 83b8d002000002 7548 a1???????? 83f8ff 7538 6a00 6a02 }
            // n = 7, score = 100
            //   83b8d002000002       | cmp                 dword ptr [eax + 0x2d0], 2
            //   7548                 | jne                 0x4a
            //   a1????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7538                 | jne                 0x3a
            //   6a00                 | push                0
            //   6a02                 | push                2

        $sequence_6 = { ff742424 e8???????? 83c410 5d 5f 5e 5b }
            // n = 7, score = 100
            //   ff742424             | push                dword ptr [esp + 0x24]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { c7461806000000 803f0a 0f84f4fdffff e9???????? c7461807000000 e9???????? 803f0a }
            // n = 7, score = 100
            //   c7461806000000       | mov                 dword ptr [esi + 0x18], 6
            //   803f0a               | cmp                 byte ptr [edi], 0xa
            //   0f84f4fdffff         | je                  0xfffffdfa
            //   e9????????           |                     
            //   c7461807000000       | mov                 dword ptr [esi + 0x18], 7
            //   e9????????           |                     
            //   803f0a               | cmp                 byte ptr [edi], 0xa

        $sequence_8 = { 8b6c241c 33db 56 57 395d00 0f8482010000 ff74241c }
            // n = 7, score = 100
            //   8b6c241c             | mov                 ebp, dword ptr [esp + 0x1c]
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   395d00               | cmp                 dword ptr [ebp], ebx
            //   0f8482010000         | je                  0x188
            //   ff74241c             | push                dword ptr [esp + 0x1c]

        $sequence_9 = { ffb650010000 ff15???????? ffb640010000 c7865001000000000000 ff15???????? 83c408 c7864001000000000000 }
            // n = 7, score = 100
            //   ffb650010000         | push                dword ptr [esi + 0x150]
            //   ff15????????         |                     
            //   ffb640010000         | push                dword ptr [esi + 0x140]
            //   c7865001000000000000     | mov    dword ptr [esi + 0x150], 0
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8
            //   c7864001000000000000     | mov    dword ptr [esi + 0x140], 0

    condition:
        7 of them and filesize < 1785856
}