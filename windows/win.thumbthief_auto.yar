rule win_thumbthief_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.thumbthief."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thumbthief"
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
        $sequence_0 = { ff15???????? 8b4d08 8b5518 29040b 8b4d0c ff01 8b4d08 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   29040b               | sub                 dword ptr [ebx + ecx], eax
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   ff01                 | inc                 dword ptr [ecx]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_1 = { eb70 68???????? eb69 8bc3 2d04130400 745b 48 }
            // n = 7, score = 100
            //   eb70                 | jmp                 0x72
            //   68????????           |                     
            //   eb69                 | jmp                 0x6b
            //   8bc3                 | mov                 eax, ebx
            //   2d04130400           | sub                 eax, 0x41304
            //   745b                 | je                  0x5d
            //   48                   | dec                 eax

        $sequence_2 = { eb09 8b4204 0fb7cb 8b3c88 ff75ec 8b45f0 8b55e0 }
            // n = 7, score = 100
            //   eb09                 | jmp                 0xb
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   0fb7cb               | movzx               ecx, bx
            //   8b3c88               | mov                 edi, dword ptr [eax + ecx*4]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]

        $sequence_3 = { ff15???????? 894608 83f8ff 751e 68???????? ff7710 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   83f8ff               | cmp                 eax, -1
            //   751e                 | jne                 0x20
            //   68????????           |                     
            //   ff7710               | push                dword ptr [edi + 0x10]
            //   ff15????????         |                     

        $sequence_4 = { ff15???????? 3d02010000 be04000000 a1???????? 0f8506010000 8da42400000000 ff7704 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102
            //   be04000000           | mov                 esi, 4
            //   a1????????           |                     
            //   0f8506010000         | jne                 0x10c
            //   8da42400000000       | lea                 esp, [esp]
            //   ff7704               | push                dword ptr [edi + 4]

        $sequence_5 = { c745fcc0bdf0ff 85f6 7421 8b4814 33d2 8955fc 85c9 }
            // n = 7, score = 100
            //   c745fcc0bdf0ff       | mov                 dword ptr [ebp - 4], 0xfff0bdc0
            //   85f6                 | test                esi, esi
            //   7421                 | je                  0x23
            //   8b4814               | mov                 ecx, dword ptr [eax + 0x14]
            //   33d2                 | xor                 edx, edx
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   85c9                 | test                ecx, ecx

        $sequence_6 = { e8???????? 8d4de0 ff7010 e8???????? 0fb786a4000000 8d4dc8 c1e80a }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   ff7010               | push                dword ptr [eax + 0x10]
            //   e8????????           |                     
            //   0fb786a4000000       | movzx               eax, word ptr [esi + 0xa4]
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   c1e80a               | shr                 eax, 0xa

        $sequence_7 = { c744881000000000 8b5df8 33c0 33ff 663b4326 0f8de9000000 8da42400000000 }
            // n = 7, score = 100
            //   c744881000000000     | mov                 dword ptr [eax + ecx*4 + 0x10], 0
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   33c0                 | xor                 eax, eax
            //   33ff                 | xor                 edi, edi
            //   663b4326             | cmp                 ax, word ptr [ebx + 0x26]
            //   0f8de9000000         | jge                 0xef
            //   8da42400000000       | lea                 esp, [esp]

        $sequence_8 = { c68518fcffff48 c7851cfcffff1cc05900 c68520fcffff49 c78524fcffffecbf5900 c68528fcffff4a c7852cfcffff7cc05900 c68530fcffff4b }
            // n = 7, score = 100
            //   c68518fcffff48       | mov                 byte ptr [ebp - 0x3e8], 0x48
            //   c7851cfcffff1cc05900     | mov    dword ptr [ebp - 0x3e4], 0x59c01c
            //   c68520fcffff49       | mov                 byte ptr [ebp - 0x3e0], 0x49
            //   c78524fcffffecbf5900     | mov    dword ptr [ebp - 0x3dc], 0x59bfec
            //   c68528fcffff4a       | mov                 byte ptr [ebp - 0x3d8], 0x4a
            //   c7852cfcffff7cc05900     | mov    dword ptr [ebp - 0x3d4], 0x59c07c
            //   c68530fcffff4b       | mov                 byte ptr [ebp - 0x3d0], 0x4b

        $sequence_9 = { e8???????? 8d85e4fdffff 8bcb 50 e8???????? 837e0800 7418 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d85e4fdffff         | lea                 eax, [ebp - 0x21c]
            //   8bcb                 | mov                 ecx, ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   837e0800             | cmp                 dword ptr [esi + 8], 0
            //   7418                 | je                  0x1a

    condition:
        7 of them and filesize < 4235264
}