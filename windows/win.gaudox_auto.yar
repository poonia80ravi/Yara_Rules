rule win_gaudox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gaudox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gaudox"
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
        $sequence_0 = { 75f4 8a01 3c2b 7406 3c2d 7503 }
            // n = 6, score = 200
            //   75f4                 | jne                 0xfffffff6
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   3c2b                 | cmp                 al, 0x2b
            //   7406                 | je                  8
            //   3c2d                 | cmp                 al, 0x2d
            //   7503                 | jne                 5

        $sequence_1 = { 7429 8d0c7b 8bfe 8d5475be 8bff 668b02 }
            // n = 6, score = 200
            //   7429                 | je                  0x2b
            //   8d0c7b               | lea                 ecx, [ebx + edi*2]
            //   8bfe                 | mov                 edi, esi
            //   8d5475be             | lea                 edx, [ebp + esi*2 - 0x42]
            //   8bff                 | mov                 edi, edi
            //   668b02               | mov                 ax, word ptr [edx]

        $sequence_2 = { 5d c20800 8b4dfc 8bd0 e8???????? 5f }
            // n = 6, score = 200
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_3 = { 895df4 8b5de8 e9???????? 33db 57 6a00 ff35???????? }
            // n = 7, score = 200
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   8b5de8               | mov                 ebx, dword ptr [ebp - 0x18]
            //   e9????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   57                   | push                edi
            //   6a00                 | push                0
            //   ff35????????         |                     

        $sequence_4 = { ff75f4 8d45f0 ff75f8 50 6a00 6a00 6a00 }
            // n = 7, score = 200
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { 56 57 c705????????00000000 8d8588fdffff 50 6a1e 6a01 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   c705????????00000000     |     
            //   8d8588fdffff         | lea                 eax, [ebp - 0x278]
            //   50                   | push                eax
            //   6a1e                 | push                0x1e
            //   6a01                 | push                1

        $sequence_6 = { 6a01 e8???????? 8bf0 85f6 7442 8d45fc 50 }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7442                 | je                  0x44
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax

        $sequence_7 = { c781fc00000002000000 a1???????? 898100010000 c7810401000002000000 a1???????? 898108010000 c7810c01000002000000 }
            // n = 7, score = 200
            //   c781fc00000002000000     | mov    dword ptr [ecx + 0xfc], 2
            //   a1????????           |                     
            //   898100010000         | mov                 dword ptr [ecx + 0x100], eax
            //   c7810401000002000000     | mov    dword ptr [ecx + 0x104], 2
            //   a1????????           |                     
            //   898108010000         | mov                 dword ptr [ecx + 0x108], eax
            //   c7810c01000002000000     | mov    dword ptr [ecx + 0x10c], 2

        $sequence_8 = { 8bff 41 803900 75fa 2bca 83f923 0f854d030000 }
            // n = 7, score = 200
            //   8bff                 | mov                 edi, edi
            //   41                   | inc                 ecx
            //   803900               | cmp                 byte ptr [ecx], 0
            //   75fa                 | jne                 0xfffffffc
            //   2bca                 | sub                 ecx, edx
            //   83f923               | cmp                 ecx, 0x23
            //   0f854d030000         | jne                 0x353

        $sequence_9 = { 034dfc c1e910 668908 eb0d 8b4dfc 660108 }
            // n = 6, score = 200
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   c1e910               | shr                 ecx, 0x10
            //   668908               | mov                 word ptr [eax], cx
            //   eb0d                 | jmp                 0xf
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   660108               | add                 word ptr [eax], cx

    condition:
        7 of them and filesize < 155648
}