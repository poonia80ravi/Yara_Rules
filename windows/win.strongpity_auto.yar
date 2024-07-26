rule win_strongpity_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.strongpity."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strongpity"
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
        $sequence_0 = { 68000000a0 6aff ff771c 56 ff15???????? 837df800 7416 }
            // n = 7, score = 700
            //   68000000a0           | push                0xa0000000
            //   6aff                 | push                -1
            //   ff771c               | push                dword ptr [edi + 0x1c]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7416                 | je                  0x18

        $sequence_1 = { 8d45f4 2bca 50 ff75cc }
            // n = 4, score = 700
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   2bca                 | sub                 ecx, edx
            //   50                   | push                eax
            //   ff75cc               | push                dword ptr [ebp - 0x34]

        $sequence_2 = { 85c0 750b 56 e8???????? 59 33f6 eb0f }
            // n = 7, score = 700
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   33f6                 | xor                 esi, esi
            //   eb0f                 | jmp                 0x11

        $sequence_3 = { 7416 8bc6 85ff 7409 }
            // n = 4, score = 700
            //   7416                 | je                  0x18
            //   8bc6                 | mov                 eax, esi
            //   85ff                 | test                edi, edi
            //   7409                 | je                  0xb

        $sequence_4 = { 33db 395f14 7520 f645f430 b8???????? 6800000020 }
            // n = 6, score = 700
            //   33db                 | xor                 ebx, ebx
            //   395f14               | cmp                 dword ptr [edi + 0x14], ebx
            //   7520                 | jne                 0x22
            //   f645f430             | test                byte ptr [ebp - 0xc], 0x30
            //   b8????????           |                     
            //   6800000020           | push                0x20000000

        $sequence_5 = { be???????? ba???????? f3a5 8bf2 }
            // n = 4, score = 700
            //   be????????           |                     
            //   ba????????           |                     
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bf2                 | mov                 esi, edx

        $sequence_6 = { ff15???????? 85c0 74b8 6a14 59 8bc6 33db }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74b8                 | je                  0xffffffba
            //   6a14                 | push                0x14
            //   59                   | pop                 ecx
            //   8bc6                 | mov                 eax, esi
            //   33db                 | xor                 ebx, ebx

        $sequence_7 = { 884612 eb09 c6461201 eb03 885e12 }
            // n = 5, score = 700
            //   884612               | mov                 byte ptr [esi + 0x12], al
            //   eb09                 | jmp                 0xb
            //   c6461201             | mov                 byte ptr [esi + 0x12], 1
            //   eb03                 | jmp                 5
            //   885e12               | mov                 byte ptr [esi + 0x12], bl

        $sequence_8 = { 5f 5e 8990d4010000 8bc5 }
            // n = 4, score = 300
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8990d4010000         | mov                 dword ptr [eax + 0x1d4], edx
            //   8bc5                 | mov                 eax, ebp

        $sequence_9 = { 5f 5e 8990d0010000 8bc5 }
            // n = 4, score = 300
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8990d0010000         | mov                 dword ptr [eax + 0x1d0], edx
            //   8bc5                 | mov                 eax, ebp

        $sequence_10 = { 012e 885c240a e9???????? 84db 0f8434020000 }
            // n = 5, score = 300
            //   012e                 | add                 dword ptr [esi], ebp
            //   885c240a             | mov                 byte ptr [esp + 0xa], bl
            //   e9????????           |                     
            //   84db                 | test                bl, bl
            //   0f8434020000         | je                  0x23a

        $sequence_11 = { 5f 5e 8bc5 5d 898a54040000 }
            // n = 5, score = 300
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8bc5                 | mov                 eax, ebp
            //   5d                   | pop                 ebp
            //   898a54040000         | mov                 dword ptr [edx + 0x454], ecx

        $sequence_12 = { 5f 5e 8990cc010000 8bc5 }
            // n = 4, score = 300
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8990cc010000         | mov                 dword ptr [eax + 0x1cc], edx
            //   8bc5                 | mov                 eax, ebp

        $sequence_13 = { 2bca 7422 49 7559 }
            // n = 4, score = 300
            //   2bca                 | sub                 ecx, edx
            //   7422                 | je                  0x24
            //   49                   | dec                 ecx
            //   7559                 | jne                 0x5b

        $sequence_14 = { 012e 885c240a ebc3 80fb5d 7520 837c240c00 0f85fe020000 }
            // n = 7, score = 300
            //   012e                 | add                 dword ptr [esi], ebp
            //   885c240a             | mov                 byte ptr [esp + 0xa], bl
            //   ebc3                 | jmp                 0xffffffc5
            //   80fb5d               | cmp                 bl, 0x5d
            //   7520                 | jne                 0x22
            //   837c240c00           | cmp                 dword ptr [esp + 0xc], 0
            //   0f85fe020000         | jne                 0x304

        $sequence_15 = { 0107 83be8800000002 8b07 0f85ad000000 83f814 }
            // n = 5, score = 300
            //   0107                 | add                 dword ptr [edi], eax
            //   83be8800000002       | cmp                 dword ptr [esi + 0x88], 2
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   0f85ad000000         | jne                 0xb3
            //   83f814               | cmp                 eax, 0x14

    condition:
        7 of them and filesize < 999424
}