rule win_doppelpaymer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.doppelpaymer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doppelpaymer"
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
        $sequence_0 = { 83ec28 6800002002 6a00 6a01 }
            // n = 4, score = 700
            //   83ec28               | sub                 esp, 0x28
            //   6800002002           | push                0x2200000
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_1 = { 80790600 7523 80790264 751d }
            // n = 4, score = 700
            //   80790600             | cmp                 byte ptr [ecx + 6], 0
            //   7523                 | jne                 0x25
            //   80790264             | cmp                 byte ptr [ecx + 2], 0x64
            //   751d                 | jne                 0x1f

        $sequence_2 = { 80790561 7517 80790361 7511 80790474 750b }
            // n = 6, score = 700
            //   80790561             | cmp                 byte ptr [ecx + 5], 0x61
            //   7517                 | jne                 0x19
            //   80790361             | cmp                 byte ptr [ecx + 3], 0x61
            //   7511                 | jne                 0x13
            //   80790474             | cmp                 byte ptr [ecx + 4], 0x74
            //   750b                 | jne                 0xd

        $sequence_3 = { 80790264 751d 80790561 7517 }
            // n = 4, score = 700
            //   80790264             | cmp                 byte ptr [ecx + 2], 0x64
            //   751d                 | jne                 0x1f
            //   80790561             | cmp                 byte ptr [ecx + 5], 0x61
            //   7517                 | jne                 0x19

        $sequence_4 = { e8???????? 8b08 e8???????? 3db6389096 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   e8????????           |                     
            //   3db6389096           | cmp                 eax, 0x969038b6

        $sequence_5 = { baffffff7f 43 e8???????? 3bd8 }
            // n = 4, score = 700
            //   baffffff7f           | mov                 edx, 0x7fffffff
            //   43                   | inc                 ebx
            //   e8????????           |                     
            //   3bd8                 | cmp                 ebx, eax

        $sequence_6 = { 8d4c2414 e8???????? 6a00 8d4c245c e8???????? 8d4608 50 }
            // n = 7, score = 600
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d4c245c             | lea                 ecx, [esp + 0x5c]
            //   e8????????           |                     
            //   8d4608               | lea                 eax, [esi + 8]
            //   50                   | push                eax

        $sequence_7 = { 8d4c2414 e8???????? 6a0f 8bcb }
            // n = 4, score = 600
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   e8????????           |                     
            //   6a0f                 | push                0xf
            //   8bcb                 | mov                 ecx, ebx

        $sequence_8 = { 81f20601081d 8b75b8 8b7e04 8b5db4 83c304 }
            // n = 5, score = 100
            //   81f20601081d         | xor                 edx, 0x1d080106
            //   8b75b8               | mov                 esi, dword ptr [ebp - 0x48]
            //   8b7e04               | mov                 edi, dword ptr [esi + 4]
            //   8b5db4               | mov                 ebx, dword ptr [ebp - 0x4c]
            //   83c304               | add                 ebx, 4

        $sequence_9 = { 890424 e8???????? 31c0 8945e4 ebe3 b8c6ea1451 }
            // n = 6, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   31c0                 | xor                 eax, eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   ebe3                 | jmp                 0xffffffe5
            //   b8c6ea1451           | mov                 eax, 0x5114eac6

        $sequence_10 = { 8b0c851c402b00 8b55ec 39d1 8945e4 894de0 733e }
            // n = 6, score = 100
            //   8b0c851c402b00       | mov                 ecx, dword ptr [eax*4 + 0x2b401c]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   39d1                 | cmp                 ecx, edx
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   733e                 | jae                 0x40

        $sequence_11 = { 6683f3f3 6639de 89ce 8945e8 894de4 8955e0 }
            // n = 6, score = 100
            //   6683f3f3             | xor                 bx, 0xfff3
            //   6639de               | cmp                 si, bx
            //   89ce                 | mov                 esi, ecx
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx

        $sequence_12 = { c1eb02 85db 7e4c 8d0cbd00000000 51 8d4d88 }
            // n = 6, score = 100
            //   c1eb02               | shr                 ebx, 2
            //   85db                 | test                ebx, ebx
            //   7e4c                 | jle                 0x4e
            //   8d0cbd00000000       | lea                 ecx, [edi*4]
            //   51                   | push                ecx
            //   8d4d88               | lea                 ecx, [ebp - 0x78]

        $sequence_13 = { 83fe00 894dbc 0f841cfeffff e9???????? 55 89e5 }
            // n = 6, score = 100
            //   83fe00               | cmp                 esi, 0
            //   894dbc               | mov                 dword ptr [ebp - 0x44], ecx
            //   0f841cfeffff         | je                  0xfffffe22
            //   e9????????           |                     
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp

        $sequence_14 = { 8bbd5cffffff 8b5f08 8b7d9c 898550ffffff 8b855cffffff 03780c 893c24 }
            // n = 7, score = 100
            //   8bbd5cffffff         | mov                 edi, dword ptr [ebp - 0xa4]
            //   8b5f08               | mov                 ebx, dword ptr [edi + 8]
            //   8b7d9c               | mov                 edi, dword ptr [ebp - 0x64]
            //   898550ffffff         | mov                 dword ptr [ebp - 0xb0], eax
            //   8b855cffffff         | mov                 eax, dword ptr [ebp - 0xa4]
            //   03780c               | add                 edi, dword ptr [eax + 0xc]
            //   893c24               | mov                 dword ptr [esp], edi

        $sequence_15 = { 893c24 895c2404 89742408 8954240c 8b5598 }
            // n = 5, score = 100
            //   893c24               | mov                 dword ptr [esp], edi
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   89742408             | mov                 dword ptr [esp + 8], esi
            //   8954240c             | mov                 dword ptr [esp + 0xc], edx
            //   8b5598               | mov                 edx, dword ptr [ebp - 0x68]

        $sequence_16 = { 89d8 c1e81f c1eb1d 898554ffffff 8b45f0 3508fcb97e 21fb }
            // n = 7, score = 100
            //   89d8                 | mov                 eax, ebx
            //   c1e81f               | shr                 eax, 0x1f
            //   c1eb1d               | shr                 ebx, 0x1d
            //   898554ffffff         | mov                 dword ptr [ebp - 0xac], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   3508fcb97e           | xor                 eax, 0x7eb9fc08
            //   21fb                 | and                 ebx, edi

        $sequence_17 = { c1eb1f 83c404 03da c745f800000000 }
            // n = 4, score = 100
            //   c1eb1f               | shr                 ebx, 0x1f
            //   83c404               | add                 esp, 4
            //   03da                 | add                 ebx, edx
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

    condition:
        7 of them and filesize < 7266304
}