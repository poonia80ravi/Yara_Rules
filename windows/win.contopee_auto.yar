rule win_contopee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.contopee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.contopee"
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
        $sequence_0 = { 7517 8d8c2438020000 6800100000 51 e8???????? 83c408 eb1f }
            // n = 7, score = 100
            //   7517                 | jne                 0x19
            //   8d8c2438020000       | lea                 ecx, [esp + 0x238]
            //   6800100000           | push                0x1000
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   eb1f                 | jmp                 0x21

        $sequence_1 = { 81c454020000 c3 8b842468020000 50 6a00 e8???????? }
            // n = 6, score = 100
            //   81c454020000         | add                 esp, 0x254
            //   c3                   | ret                 
            //   8b842468020000       | mov                 eax, dword ptr [esp + 0x268]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_2 = { b981000000 33c0 8d7c244a 6689542408 f3ab }
            // n = 5, score = 100
            //   b981000000           | mov                 ecx, 0x81
            //   33c0                 | xor                 eax, eax
            //   8d7c244a             | lea                 edi, [esp + 0x4a]
            //   6689542408           | mov                 word ptr [esp + 8], dx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_3 = { e8???????? 83c410 85c0 7ede 8d44241c 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7ede                 | jle                 0xffffffe0
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   50                   | push                eax

        $sequence_4 = { 56 57 e8???????? 83c410 33db 8b54240c 52 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   33db                 | xor                 ebx, ebx
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   52                   | push                edx

        $sequence_5 = { 3bc8 7602 b301 890d???????? 8ac3 }
            // n = 5, score = 100
            //   3bc8                 | cmp                 ecx, eax
            //   7602                 | jbe                 4
            //   b301                 | mov                 bl, 1
            //   890d????????         |                     
            //   8ac3                 | mov                 al, bl

        $sequence_6 = { 668b88780a0110 898a8c000000 33c9 668b887c0a0110 898a90000000 33c9 668b887e0a0110 }
            // n = 7, score = 100
            //   668b88780a0110       | mov                 cx, word ptr [eax + 0x10010a78]
            //   898a8c000000         | mov                 dword ptr [edx + 0x8c], ecx
            //   33c9                 | xor                 ecx, ecx
            //   668b887c0a0110       | mov                 cx, word ptr [eax + 0x10010a7c]
            //   898a90000000         | mov                 dword ptr [edx + 0x90], ecx
            //   33c9                 | xor                 ecx, ecx
            //   668b887e0a0110       | mov                 cx, word ptr [eax + 0x10010a7e]

        $sequence_7 = { 56 8b742408 8b4608 85c0 740f 6a64 ff15???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   6a64                 | push                0x64
            //   ff15????????         |                     

        $sequence_8 = { 8b0d???????? a1???????? 83c408 0bc8 7535 6a00 ff15???????? }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   a1????????           |                     
            //   83c408               | add                 esp, 8
            //   0bc8                 | or                  ecx, eax
            //   7535                 | jne                 0x37
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_9 = { 88907a060000 eb10 663dffff 750a 8b4d00 c6817a06000000 8b4500 }
            // n = 7, score = 100
            //   88907a060000         | mov                 byte ptr [eax + 0x67a], dl
            //   eb10                 | jmp                 0x12
            //   663dffff             | cmp                 ax, 0xffff
            //   750a                 | jne                 0xc
            //   8b4d00               | mov                 ecx, dword ptr [ebp]
            //   c6817a06000000       | mov                 byte ptr [ecx + 0x67a], 0
            //   8b4500               | mov                 eax, dword ptr [ebp]

    condition:
        7 of them and filesize < 180224
}