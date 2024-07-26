rule win_redsalt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.redsalt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redsalt"
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
        $sequence_0 = { 83c414 33c9 83f8ff 0f95c1 }
            // n = 4, score = 1100
            //   83c414               | add                 esp, 0x14
            //   33c9                 | xor                 ecx, ecx
            //   83f8ff               | cmp                 eax, -1
            //   0f95c1               | setne               cl

        $sequence_1 = { 750b 68e8030000 ff15???????? e8???????? 85c0 }
            // n = 5, score = 1100
            //   750b                 | jne                 0xd
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_2 = { 85c0 7515 c705????????01000000 ff15???????? e9???????? }
            // n = 5, score = 900
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   c705????????01000000     |     
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_3 = { c745d060ea0000 6a04 8d45d0 50 6806100000 68ffff0000 }
            // n = 6, score = 900
            //   c745d060ea0000       | mov                 dword ptr [ebp - 0x30], 0xea60
            //   6a04                 | push                4
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax
            //   6806100000           | push                0x1006
            //   68ffff0000           | push                0xffff

        $sequence_4 = { e8???????? 85c0 750a 6a32 }
            // n = 4, score = 900
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   6a32                 | push                0x32

        $sequence_5 = { 51 ffd6 85c0 7510 }
            // n = 4, score = 900
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12

        $sequence_6 = { 85f6 7c0e 83fe7f 7f09 }
            // n = 4, score = 800
            //   85f6                 | test                esi, esi
            //   7c0e                 | jl                  0x10
            //   83fe7f               | cmp                 esi, 0x7f
            //   7f09                 | jg                  0xb

        $sequence_7 = { eb03 83c9ff 85f6 7c0e }
            // n = 4, score = 800
            //   eb03                 | jmp                 5
            //   83c9ff               | or                  ecx, 0xffffffff
            //   85f6                 | test                esi, esi
            //   7c0e                 | jl                  0x10

        $sequence_8 = { 8b5508 52 e8???????? 83c414 6a00 6a01 }
            // n = 6, score = 800
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_9 = { c60100 5f 5e 33c0 }
            // n = 4, score = 700
            //   c60100               | mov                 byte ptr [ecx], 0
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { 6a00 52 c744242401000000 8944242c c744243002000000 }
            // n = 5, score = 700
            //   6a00                 | push                0
            //   52                   | push                edx
            //   c744242401000000     | mov                 dword ptr [esp + 0x24], 1
            //   8944242c             | mov                 dword ptr [esp + 0x2c], eax
            //   c744243002000000     | mov                 dword ptr [esp + 0x30], 2

        $sequence_11 = { 7509 80780120 7503 83c002 }
            // n = 4, score = 700
            //   7509                 | jne                 0xb
            //   80780120             | cmp                 byte ptr [eax + 1], 0x20
            //   7503                 | jne                 5
            //   83c002               | add                 eax, 2

        $sequence_12 = { 8d8530fcffff 50 e8???????? 83c40c }
            // n = 4, score = 700
            //   8d8530fcffff         | lea                 eax, [ebp - 0x3d0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_13 = { e8???????? 83c408 6800010000 68???????? }
            // n = 4, score = 600
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6800010000           | push                0x100
            //   68????????           |                     

        $sequence_14 = { e8???????? 50 6804010000 68???????? }
            // n = 4, score = 600
            //   e8????????           |                     
            //   50                   | push                eax
            //   6804010000           | push                0x104
            //   68????????           |                     

        $sequence_15 = { 833800 750f c705????????01000000 e9???????? }
            // n = 4, score = 500
            //   833800               | cmp                 dword ptr [eax], 0
            //   750f                 | jne                 0x11
            //   c705????????01000000     |     
            //   e9????????           |                     

        $sequence_16 = { c3 8b6c2424 894c2414 8b4c2420 c1e902 }
            // n = 5, score = 500
            //   c3                   | ret                 
            //   8b6c2424             | mov                 ebp, dword ptr [esp + 0x24]
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   c1e902               | shr                 ecx, 2

        $sequence_17 = { d1ed 33c0 83ef03 8a06 83c603 c1e802 41 }
            // n = 7, score = 500
            //   d1ed                 | shr                 ebp, 1
            //   33c0                 | xor                 eax, eax
            //   83ef03               | sub                 edi, 3
            //   8a06                 | mov                 al, byte ptr [esi]
            //   83c603               | add                 esi, 3
            //   c1e802               | shr                 eax, 2
            //   41                   | inc                 ecx

        $sequence_18 = { c644243423 c644243572 c64424367a c644243700 }
            // n = 4, score = 300
            //   c644243423           | mov                 byte ptr [esp + 0x34], 0x23
            //   c644243572           | mov                 byte ptr [esp + 0x35], 0x72
            //   c64424367a           | mov                 byte ptr [esp + 0x36], 0x7a
            //   c644243700           | mov                 byte ptr [esp + 0x37], 0

        $sequence_19 = { d2cc bbe3b46b7e 6aa2 dd45ff }
            // n = 4, score = 200
            //   d2cc                 | ror                 ah, cl
            //   bbe3b46b7e           | mov                 ebx, 0x7e6bb4e3
            //   6aa2                 | push                -0x5e
            //   dd45ff               | fld                 qword ptr [ebp - 1]

        $sequence_20 = { de6c58ae c8201cdd f7be5b408d58 1b7f01 d2cc }
            // n = 5, score = 200
            //   de6c58ae             | fisubr              word ptr [eax + ebx*2 - 0x52]
            //   c8201cdd             | enter               0x1c20, -0x23
            //   f7be5b408d58         | idiv                dword ptr [esi + 0x588d405b]
            //   1b7f01               | sbb                 edi, dword ptr [edi + 1]
            //   d2cc                 | ror                 ah, cl

        $sequence_21 = { e9???????? 48895c2408 57 4883ec20 33db 4c8bc1 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   48895c2408           | push                edi
            //   57                   | dec                 eax
            //   4883ec20             | sub                 esp, 0x20
            //   33db                 | dec                 eax
            //   4c8bc1               | mov                 dword ptr [esp + 8], ebx

        $sequence_22 = { e9???????? 48895c2408 4889742410 57 4883ec20 488b7978 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   48895c2408           | dec                 eax
            //   4889742410           | mov                 dword ptr [esp + 8], ebx
            //   57                   | dec                 eax
            //   4883ec20             | mov                 dword ptr [esp + 0x10], esi
            //   488b7978             | push                edi

        $sequence_23 = { e9???????? 48895c2408 4889742448 894208 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   48895c2408           | mov                 dword ptr [esp + 8], ebx
            //   4889742448           | dec                 eax
            //   894208               | mov                 dword ptr [esp + 0x10], esi

        $sequence_24 = { e9???????? 48895c2408 4889742418 57 4881ec80000000 }
            // n = 5, score = 100
            //   e9????????           |                     
            //   48895c2408           | mov                 edi, edx
            //   4889742418           | mov                 ebx, ecx
            //   57                   | dec                 eax
            //   4881ec80000000       | mov                 dword ptr [esp + 8], ebx

    condition:
        7 of them and filesize < 2957312
}