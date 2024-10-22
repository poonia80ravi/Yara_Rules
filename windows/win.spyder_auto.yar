rule win_spyder_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.spyder."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyder"
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
        $sequence_0 = { 488d3d60930000 eb0e 488b03 4885c0 }
            // n = 4, score = 500
            //   488d3d60930000       | dec                 eax
            //   eb0e                 | test                eax, eax
            //   488b03               | je                  0x199
            //   4885c0               | dec                 eax

        $sequence_1 = { 663901 740b b9c1000000 ff15???????? 496374243c 4903f4 813e50450000 }
            // n = 7, score = 500
            //   663901               | lea                 ecx, [0xa2d3]
            //   740b                 | test                eax, eax
            //   b9c1000000           | jne                 0x5c
            //   ff15????????         |                     
            //   496374243c           | dec                 eax
            //   4903f4               | lea                 ecx, [0x3313]
            //   813e50450000         | dec                 eax

        $sequence_2 = { 488bf8 0f85d5000000 488d0d935f0000 ff15???????? 488bf0 4885c0 0f8493010000 }
            // n = 7, score = 500
            //   488bf8               | dec                 eax
            //   0f85d5000000         | mov                 dword ptr [ecx + 0xa0], eax
            //   488d0d935f0000       | and                 dword ptr [ecx + 0x10], 0
            //   ff15????????         |                     
            //   488bf0               | dec                 eax
            //   4885c0               | mov                 edi, eax
            //   0f8493010000         | jne                 0xdb

        $sequence_3 = { 488bd9 488d05b1840000 488981a0000000 83611000 }
            // n = 4, score = 500
            //   488bd9               | dec                 eax
            //   488d05b1840000       | mov                 ebx, ecx
            //   488981a0000000       | dec                 eax
            //   83611000             | lea                 eax, [0x84b1]

        $sequence_4 = { 488d15005f0000 488bce 488905???????? ff15???????? 488bc8 ff15???????? }
            // n = 6, score = 500
            //   488d15005f0000       | lea                 edi, [0x9360]
            //   488bce               | jmp                 0x17
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488bc8               | dec                 eax
            //   ff15????????         |                     

        $sequence_5 = { b9c1000000 ff15???????? 8b5650 488b4e30 }
            // n = 4, score = 500
            //   b9c1000000           | mov                 eax, dword ptr [ebx]
            //   ff15????????         |                     
            //   8b5650               | dec                 eax
            //   488b4e30             | test                eax, eax

        $sequence_6 = { ff15???????? 418d7c24e7 85c0 752a 4c8d05928a0000 8bd7 }
            // n = 6, score = 500
            //   ff15????????         |                     
            //   418d7c24e7           | cmp                 word ptr [ecx], ax
            //   85c0                 | je                  0x10
            //   752a                 | mov                 ecx, 0xc1
            //   4c8d05928a0000       | dec                 ecx
            //   8bd7                 | arpl                word ptr [esp + 0x3c], si

        $sequence_7 = { 488d0dd3a20000 e8???????? 85c0 755a 488d0d13330000 }
            // n = 5, score = 500
            //   488d0dd3a20000       | dec                 eax
            //   e8????????           |                     
            //   85c0                 | lea                 ecx, [0x5f93]
            //   755a                 | dec                 eax
            //   488d0d13330000       | mov                 esi, eax

        $sequence_8 = { 890d???????? 8915???????? 5f 5e 5d 5b }
            // n = 6, score = 100
            //   890d????????         |                     
            //   8915????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_9 = { 59 8b4d08 8a11 0fb6c2 0fb6f8 f687014a091004 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   0fb6c2               | movzx               eax, dl
            //   0fb6f8               | movzx               edi, al
            //   f687014a091004       | test                byte ptr [edi + 0x10094a01], 4

        $sequence_10 = { 8db6ec3c0910 6a00 50 ff36 }
            // n = 4, score = 100
            //   8db6ec3c0910         | lea                 esi, [esi + 0x10093cec]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   ff36                 | push                dword ptr [esi]

        $sequence_11 = { aa 8d842490150000 50 51 68ff030000 }
            // n = 5, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d842490150000       | lea                 eax, [esp + 0x1590]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   68ff030000           | push                0x3ff

        $sequence_12 = { 2bf9 682b010000 8bf7 8be9 8bfa }
            // n = 5, score = 100
            //   2bf9                 | sub                 edi, ecx
            //   682b010000           | push                0x12b
            //   8bf7                 | mov                 esi, edi
            //   8be9                 | mov                 ebp, ecx
            //   8bfa                 | mov                 edi, edx

        $sequence_13 = { 8b0c8d204b0910 8d04c0 80648104fd 8d448104 }
            // n = 4, score = 100
            //   8b0c8d204b0910       | mov                 ecx, dword ptr [ecx*4 + 0x10094b20]
            //   8d04c0               | lea                 eax, [eax + eax*8]
            //   80648104fd           | and                 byte ptr [ecx + eax*4 + 4], 0xfd
            //   8d448104             | lea                 eax, [ecx + eax*4 + 4]

        $sequence_14 = { f682014a091004 740c ff01 85f6 7406 8a10 8816 }
            // n = 7, score = 100
            //   f682014a091004       | test                byte ptr [edx + 0x10094a01], 4
            //   740c                 | je                  0xe
            //   ff01                 | inc                 dword ptr [ecx]
            //   85f6                 | test                esi, esi
            //   7406                 | je                  8
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   8816                 | mov                 byte ptr [esi], dl

        $sequence_15 = { 47 83f80b 0f8777020000 ff2485978a0010 80fb31 7c0c 80fb39 }
            // n = 7, score = 100
            //   47                   | inc                 edi
            //   83f80b               | cmp                 eax, 0xb
            //   0f8777020000         | ja                  0x27d
            //   ff2485978a0010       | jmp                 dword ptr [eax*4 + 0x10008a97]
            //   80fb31               | cmp                 bl, 0x31
            //   7c0c                 | jl                  0xe
            //   80fb39               | cmp                 bl, 0x39

    condition:
        7 of them and filesize < 1458176
}