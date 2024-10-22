rule win_absentloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.absentloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.absentloader"
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
        $sequence_0 = { 5f 8b448dd8 83e876 6bc019 99 f7ff 8d0417 }
            // n = 7, score = 200
            //   5f                   | pop                 edi
            //   8b448dd8             | mov                 eax, dword ptr [ebp + ecx*4 - 0x28]
            //   83e876               | sub                 eax, 0x76
            //   6bc019               | imul                eax, eax, 0x19
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi
            //   8d0417               | lea                 eax, [edi + edx]

        $sequence_1 = { e8???????? 894628 83f80d 0f84d1feffff 83f80a 0f8506040000 8bcf }
            // n = 7, score = 200
            //   e8????????           |                     
            //   894628               | mov                 dword ptr [esi + 0x28], eax
            //   83f80d               | cmp                 eax, 0xd
            //   0f84d1feffff         | je                  0xfffffed7
            //   83f80a               | cmp                 eax, 0xa
            //   0f8506040000         | jne                 0x40c
            //   8bcf                 | mov                 ecx, edi

        $sequence_2 = { 5e 5d c20400 8d4104 c701ac1205fd 50 }
            // n = 6, score = 200
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   8d4104               | lea                 eax, [ecx + 4]
            //   c701ac1205fd         | mov                 dword ptr [ecx], 0xfd0512ac
            //   50                   | push                eax

        $sequence_3 = { 8034082e 40 83f80e 72f6 8bc1 c3 80791300 }
            // n = 7, score = 200
            //   8034082e             | xor                 byte ptr [eax + ecx], 0x2e
            //   40                   | inc                 eax
            //   83f80e               | cmp                 eax, 0xe
            //   72f6                 | jb                  0xfffffff8
            //   8bc1                 | mov                 eax, ecx
            //   c3                   | ret                 
            //   80791300             | cmp                 byte ptr [ecx + 0x13], 0

        $sequence_4 = { 8d75a4 a5 a5 a5 a5 e8???????? }
            // n = 6, score = 200
            //   8d75a4               | lea                 esi, [ebp - 0x5c]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     

        $sequence_5 = { 686c6005fd 57 56 e8???????? 83c40c 85c0 0f85e5000000 }
            // n = 7, score = 200
            //   686c6005fd           | push                0xfd05606c
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f85e5000000         | jne                 0xeb

        $sequence_6 = { c70406481f05fd 8b06 8b4804 8d41f8 894431fc 8b03 8b4004 }
            // n = 7, score = 200
            //   c70406481f05fd       | mov                 dword ptr [esi + eax], 0xfd051f48
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8d41f8               | lea                 eax, [ecx - 8]
            //   894431fc             | mov                 dword ptr [ecx + esi - 4], eax
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_7 = { 84c9 7507 85f6 7430 56 eb36 8b8368020000 }
            // n = 7, score = 200
            //   84c9                 | test                cl, cl
            //   7507                 | jne                 9
            //   85f6                 | test                esi, esi
            //   7430                 | je                  0x32
            //   56                   | push                esi
            //   eb36                 | jmp                 0x38
            //   8b8368020000         | mov                 eax, dword ptr [ebx + 0x268]

        $sequence_8 = { 8a0a 42 84c9 75ee 89b5f0fdffff 81bdf0fdffff638bd4c3 8b7018 }
            // n = 7, score = 200
            //   8a0a                 | mov                 cl, byte ptr [edx]
            //   42                   | inc                 edx
            //   84c9                 | test                cl, cl
            //   75ee                 | jne                 0xfffffff0
            //   89b5f0fdffff         | mov                 dword ptr [ebp - 0x210], esi
            //   81bdf0fdffff638bd4c3     | cmp    dword ptr [ebp - 0x210], 0xc3d48b63
            //   8b7018               | mov                 esi, dword ptr [eax + 0x18]

        $sequence_9 = { 84db 743b 8b4608 8378fc00 7432 83ec10 8d4668 }
            // n = 7, score = 200
            //   84db                 | test                bl, bl
            //   743b                 | je                  0x3d
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8378fc00             | cmp                 dword ptr [eax - 4], 0
            //   7432                 | je                  0x34
            //   83ec10               | sub                 esp, 0x10
            //   8d4668               | lea                 eax, [esi + 0x68]

    condition:
        7 of them and filesize < 794624
}