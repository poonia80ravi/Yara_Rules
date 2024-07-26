rule win_tidepool_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.tidepool."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tidepool"
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
        $sequence_0 = { 83c404 8bc6 5e c20400 80790800 }
            // n = 5, score = 1000
            //   83c404               | add                 esp, 4
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   80790800             | cmp                 byte ptr [ecx + 8], 0

        $sequence_1 = { 6a00 50 8b08 ff91a4000000 }
            // n = 4, score = 1000
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff91a4000000         | call                dword ptr [ecx + 0xa4]

        $sequence_2 = { 5e 5b 8b8d00030000 33cd e8???????? }
            // n = 5, score = 1000
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8b8d00030000         | mov                 ecx, dword ptr [ebp + 0x300]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     

        $sequence_3 = { 83e906 51 83c006 50 }
            // n = 4, score = 900
            //   83e906               | sub                 ecx, 6
            //   51                   | push                ecx
            //   83c006               | add                 eax, 6
            //   50                   | push                eax

        $sequence_4 = { 53 6a02 8bf1 e8???????? }
            // n = 4, score = 900
            //   53                   | push                ebx
            //   6a02                 | push                2
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     

        $sequence_5 = { e8???????? 83c40c 803d????????37 7518 68???????? }
            // n = 5, score = 900
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   803d????????37       |                     
            //   7518                 | jne                 0x1a
            //   68????????           |                     

        $sequence_6 = { 6800000040 8d4500 50 ff15???????? }
            // n = 4, score = 900
            //   6800000040           | push                0x40000000
            //   8d4500               | lea                 eax, [ebp]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { b900000400 c60000 40 49 75f9 }
            // n = 5, score = 800
            //   b900000400           | mov                 ecx, 0x40000
            //   c60000               | mov                 byte ptr [eax], 0
            //   40                   | inc                 eax
            //   49                   | dec                 ecx
            //   75f9                 | jne                 0xfffffffb

        $sequence_8 = { 75f9 b8???????? b900000400 c60000 }
            // n = 4, score = 800
            //   75f9                 | jne                 0xfffffffb
            //   b8????????           |                     
            //   b900000400           | mov                 ecx, 0x40000
            //   c60000               | mov                 byte ptr [eax], 0

        $sequence_9 = { 6810270000 ff15???????? 8b45ec 8b08 }
            // n = 4, score = 800
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_10 = { 7509 8b4654 50 8b08 }
            // n = 4, score = 800
            //   7509                 | jne                 0xb
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_11 = { e8???????? 68???????? 68???????? 68???????? 8d4500 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     
            //   8d4500               | lea                 eax, [ebp]

        $sequence_12 = { 57 50 6802020000 ff15???????? 68???????? }
            // n = 5, score = 800
            //   57                   | push                edi
            //   50                   | push                eax
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_13 = { 52 50 ff91d0000000 33ff }
            // n = 4, score = 800
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff91d0000000         | call                dword ptr [ecx + 0xd0]
            //   33ff                 | xor                 edi, edi

        $sequence_14 = { 681f000200 56 68???????? 6801000080 }
            // n = 4, score = 800
            //   681f000200           | push                0x2001f
            //   56                   | push                esi
            //   68????????           |                     
            //   6801000080           | push                0x80000001

        $sequence_15 = { c3 ff25???????? 51 8d4c2404 2bc8 }
            // n = 5, score = 800
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   51                   | push                ecx
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   2bc8                 | sub                 ecx, eax

        $sequence_16 = { 5d 51 c3 55 8bec 81ec28030000 a3???????? }
            // n = 7, score = 800
            //   5d                   | pop                 ebp
            //   51                   | push                ecx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec28030000         | sub                 esp, 0x328
            //   a3????????           |                     

        $sequence_17 = { 8d9698000000 52 8d5678 8b08 }
            // n = 4, score = 800
            //   8d9698000000         | lea                 edx, [esi + 0x98]
            //   52                   | push                edx
            //   8d5678               | lea                 edx, [esi + 0x78]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_18 = { 8d45ec 50 681f000200 53 }
            // n = 4, score = 800
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   681f000200           | push                0x2001f
            //   53                   | push                ebx

        $sequence_19 = { 56 8bf1 e8???????? 8b4654 6a00 }
            // n = 5, score = 800
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8b4654               | mov                 eax, dword ptr [esi + 0x54]
            //   6a00                 | push                0

        $sequence_20 = { 68fe000000 56 8d856afdffff 50 e8???????? 6689b568feffff 68fe000000 }
            // n = 7, score = 700
            //   68fe000000           | push                0xfe
            //   56                   | push                esi
            //   8d856afdffff         | lea                 eax, [ebp - 0x296]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6689b568feffff       | mov                 word ptr [ebp - 0x198], si
            //   68fe000000           | push                0xfe

        $sequence_21 = { c1ea10 80fa3d 0f84b3000000 8ad8 }
            // n = 4, score = 600
            //   c1ea10               | shr                 edx, 0x10
            //   80fa3d               | cmp                 dl, 0x3d
            //   0f84b3000000         | je                  0xb9
            //   8ad8                 | mov                 bl, al

        $sequence_22 = { 0bcf 836c241401 8948fd 0f85bdfdffff 8b442418 8b4c2424 }
            // n = 6, score = 600
            //   0bcf                 | or                  ecx, edi
            //   836c241401           | sub                 dword ptr [esp + 0x14], 1
            //   8948fd               | mov                 dword ptr [eax - 3], ecx
            //   0f85bdfdffff         | jne                 0xfffffdc3
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]

        $sequence_23 = { 89542418 8b5500 83ceff 80fa41 }
            // n = 4, score = 600
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   8b5500               | mov                 edx, dword ptr [ebp]
            //   83ceff               | or                  esi, 0xffffffff
            //   80fa41               | cmp                 dl, 0x41

        $sequence_24 = { ff75ec ff15???????? 8b35???????? 6a04 }
            // n = 4, score = 400
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   6a04                 | push                4

        $sequence_25 = { e8???????? 8b37 83c410 83fb02 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   83c410               | add                 esp, 0x10
            //   83fb02               | cmp                 ebx, 2

        $sequence_26 = { 8b7d08 8d0514500110 83780800 753b b0ff 8bff 0ac0 }
            // n = 7, score = 200
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d0514500110         | lea                 eax, [0x10015014]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   753b                 | jne                 0x3d
            //   b0ff                 | mov                 al, 0xff
            //   8bff                 | mov                 edi, edi
            //   0ac0                 | or                  al, al

        $sequence_27 = { 8b45f8 03c6 50 e8???????? 8345f808 8d45d8 6a08 }
            // n = 7, score = 200
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8345f808             | add                 dword ptr [ebp - 8], 8
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   6a08                 | push                8

        $sequence_28 = { 8b5d0c 83c40c 53 ff15???????? 8d45a4 50 }
            // n = 6, score = 200
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   83c40c               | add                 esp, 0xc
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax

        $sequence_29 = { 7583 b001 5f 5e 5b }
            // n = 5, score = 200
            //   7583                 | jne                 0xffffff85
            //   b001                 | mov                 al, 1
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_30 = { 0fb6da f6830152011004 740c ff01 85f6 7405 8a18 }
            // n = 7, score = 200
            //   0fb6da               | movzx               ebx, dl
            //   f6830152011004       | test                byte ptr [ebx + 0x10015201], 4
            //   740c                 | je                  0xe
            //   ff01                 | inc                 dword ptr [ecx]
            //   85f6                 | test                esi, esi
            //   7405                 | je                  7
            //   8a18                 | mov                 bl, byte ptr [eax]

    condition:
        7 of them and filesize < 1998848
}