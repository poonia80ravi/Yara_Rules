rule win_grateful_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.grateful_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grateful_pos"
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
        $sequence_0 = { 7411 e8???????? e8???????? 33c0 e9???????? }
            // n = 5, score = 600
            //   7411                 | je                  0x13
            //   e8????????           |                     
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     

        $sequence_1 = { 7407 b8f6ffffff eb02 33c0 }
            // n = 4, score = 600
            //   7407                 | je                  9
            //   b8f6ffffff           | mov                 eax, 0xfffffff6
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { e8???????? 99 b980ee3600 f7f9 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b980ee3600           | mov                 ecx, 0x36ee80
            //   f7f9                 | idiv                ecx

        $sequence_3 = { b8feffffff eb1a b8fdffffff eb13 b8fcffffff eb0c }
            // n = 6, score = 600
            //   b8feffffff           | mov                 eax, 0xfffffffe
            //   eb1a                 | jmp                 0x1c
            //   b8fdffffff           | mov                 eax, 0xfffffffd
            //   eb13                 | jmp                 0x15
            //   b8fcffffff           | mov                 eax, 0xfffffffc
            //   eb0c                 | jmp                 0xe

        $sequence_4 = { eb07 b8fcffffff eb02 33c0 }
            // n = 4, score = 600
            //   eb07                 | jmp                 9
            //   b8fcffffff           | mov                 eax, 0xfffffffc
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 83f801 7510 e8???????? e8???????? }
            // n = 4, score = 600
            //   83f801               | cmp                 eax, 1
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_6 = { 83bdd8fbffffff 7502 eb76 8b95dcfbffff 81e200100000 }
            // n = 5, score = 500
            //   83bdd8fbffffff       | mov                 eax, dword ptr [edx]
            //   7502                 | push                eax
            //   eb76                 | push                0
            //   8b95dcfbffff         | mov                 ecx, dword ptr [ebp - 0x40c]
            //   81e200100000         | push                ecx

        $sequence_7 = { 6a00 8b8df4fbffff 51 e8???????? 8d95fcfbffff }
            // n = 5, score = 500
            //   6a00                 | pop                 ebp
            //   8b8df4fbffff         | add                 ecx, dword ptr [ebp - 0x20008]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d95fcfbffff         | mov                 edx, dword ptr [ebp + 8]

        $sequence_8 = { c785c8fbffff10000000 6a04 8d95c8fbffff 52 8b4518 }
            // n = 5, score = 500
            //   c785c8fbffff10000000     | add    esp, 4
            //   6a04                 | mov                 dword ptr [ebp - 0x410], eax
            //   8d95c8fbffff         | push                0x400
            //   52                   | mov                 eax, dword ptr [ebp - 0x410]
            //   8b4518               | push                eax

        $sequence_9 = { 8b8d6cf9ffff c1e10a 81c1???????? 51 }
            // n = 4, score = 500
            //   8b8d6cf9ffff         | mov                 ecx, dword ptr [ebp - 0x694]
            //   c1e10a               | shl                 ecx, 0xa
            //   81c1????????         |                     
            //   51                   | push                ecx

        $sequence_10 = { e8???????? 83c404 8985f0fbffff 6800040000 8b85f0fbffff 50 8b8df4fbffff }
            // n = 7, score = 500
            //   e8????????           |                     
            //   83c404               | lea                 edx, [ebp - 0x404]
            //   8985f0fbffff         | cmp                 dword ptr [ebp - 0x428], -1
            //   6800040000           | jne                 0xb
            //   8b85f0fbffff         | jmp                 0x78
            //   50                   | mov                 edx, dword ptr [ebp - 0x424]
            //   8b8df4fbffff         | and                 edx, 0x1000

        $sequence_11 = { c705????????00000000 eb0d a1???????? 83c001 a3???????? 8b4d08 51 }
            // n = 7, score = 500
            //   c705????????00000000     |     
            //   eb0d                 | mov                 ecx, dword ptr [ebp - 0x40c]
            //   a1????????           |                     
            //   83c001               | mov                 dword ptr [ebp - 0x438], 0x10
            //   a3????????           |                     
            //   8b4d08               | push                4
            //   51                   | lea                 edx, [ebp - 0x438]

        $sequence_12 = { 038df8fffdff 51 8b5508 8b02 50 }
            // n = 5, score = 500
            //   038df8fffdff         | push                ecx
            //   51                   | test                eax, eax
            //   8b5508               | jne                 3
            //   8b02                 | inc                 eax
            //   50                   | push                eax

        $sequence_13 = { 898de0fffdff 8d95e8fffdff 52 8b85e0fffdff 50 }
            // n = 5, score = 500
            //   898de0fffdff         | mov                 dword ptr [ebp - 0x20020], ecx
            //   8d95e8fffdff         | lea                 edx, [ebp - 0x20018]
            //   52                   | push                edx
            //   8b85e0fffdff         | mov                 eax, dword ptr [ebp - 0x20020]
            //   50                   | push                eax

        $sequence_14 = { 486bc019 488d0d0dde0100 0fbe0401 83f04d }
            // n = 4, score = 200
            //   486bc019             | dec                 eax
            //   488d0d0dde0100       | lea                 ecx, [0x502d]
            //   0fbe0401             | dec                 eax
            //   83f04d               | imul                eax, eax, 0x19

        $sequence_15 = { 8805???????? b801000000 486bc03f 488d0d2d500000 }
            // n = 4, score = 200
            //   8805????????         |                     
            //   b801000000           | mov                 eax, 1
            //   486bc03f             | dec                 eax
            //   488d0d2d500000       | imul                eax, eax, 0x3f

    condition:
        7 of them and filesize < 3964928
}