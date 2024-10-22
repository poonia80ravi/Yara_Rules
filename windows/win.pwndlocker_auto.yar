rule win_pwndlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pwndlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pwndlocker"
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
        $sequence_0 = { c1cf0d 01c7 ebf4 3b7df0 75e0 5a }
            // n = 6, score = 300
            //   c1cf0d               | ror                 edi, 0xd
            //   01c7                 | add                 edi, eax
            //   ebf4                 | jmp                 0xfffffff6
            //   3b7df0               | cmp                 edi, dword ptr [ebp - 0x10]
            //   75e0                 | jne                 0xffffffe2
            //   5a                   | pop                 edx

        $sequence_1 = { 01d8 83c078 8b00 8d3403 8b4e18 }
            // n = 5, score = 300
            //   01d8                 | add                 eax, ebx
            //   83c078               | add                 eax, 0x78
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8d3403               | lea                 esi, [ebx + eax]
            //   8b4e18               | mov                 ecx, dword ptr [esi + 0x18]

        $sequence_2 = { c1cf0d 01c7 ebf4 3b7df0 }
            // n = 4, score = 300
            //   c1cf0d               | ror                 edi, 0xd
            //   01c7                 | add                 edi, eax
            //   ebf4                 | jmp                 0xfffffff6
            //   3b7df0               | cmp                 edi, dword ptr [ebp - 0x10]

        $sequence_3 = { ebf4 3b7df0 75e0 5a 8b7224 01de 31c0 }
            // n = 7, score = 300
            //   ebf4                 | jmp                 0xfffffff6
            //   3b7df0               | cmp                 edi, dword ptr [ebp - 0x10]
            //   75e0                 | jne                 0xffffffe2
            //   5a                   | pop                 edx
            //   8b7224               | mov                 esi, dword ptr [edx + 0x24]
            //   01de                 | add                 esi, ebx
            //   31c0                 | xor                 eax, eax

        $sequence_4 = { 31ff 31c0 fc ac 84c0 7407 }
            // n = 6, score = 300
            //   31ff                 | xor                 edi, edi
            //   31c0                 | xor                 eax, eax
            //   fc                   | cld                 
            //   ac                   | lodsb               al, byte ptr [esi]
            //   84c0                 | test                al, al
            //   7407                 | je                  9

        $sequence_5 = { c1cf0d 01c7 ebf4 3b7df0 75e0 5a 8b7224 }
            // n = 7, score = 300
            //   c1cf0d               | ror                 edi, 0xd
            //   01c7                 | add                 edi, eax
            //   ebf4                 | jmp                 0xfffffff6
            //   3b7df0               | cmp                 edi, dword ptr [ebp - 0x10]
            //   75e0                 | jne                 0xffffffe2
            //   5a                   | pop                 edx
            //   8b7224               | mov                 esi, dword ptr [edx + 0x24]

        $sequence_6 = { 01de 31ff 31c0 fc }
            // n = 4, score = 300
            //   01de                 | add                 esi, ebx
            //   31ff                 | xor                 edi, edi
            //   31c0                 | xor                 eax, eax
            //   fc                   | cld                 

        $sequence_7 = { 668b044e 8b721c 01de 8b0486 }
            // n = 4, score = 300
            //   668b044e             | mov                 ax, word ptr [esi + ecx*2]
            //   8b721c               | mov                 esi, dword ptr [edx + 0x1c]
            //   01de                 | add                 esi, ebx
            //   8b0486               | mov                 eax, dword ptr [esi + eax*4]

        $sequence_8 = { fc ac 84c0 7407 c1cf0d 01c7 ebf4 }
            // n = 7, score = 300
            //   fc                   | cld                 
            //   ac                   | lodsb               al, byte ptr [esi]
            //   84c0                 | test                al, al
            //   7407                 | je                  9
            //   c1cf0d               | ror                 edi, 0xd
            //   01c7                 | add                 edi, eax
            //   ebf4                 | jmp                 0xfffffff6

        $sequence_9 = { 01da 56 e334 49 8d348a }
            // n = 5, score = 300
            //   01da                 | add                 edx, ebx
            //   56                   | push                esi
            //   e334                 | jecxz               0x36
            //   49                   | dec                 ecx
            //   8d348a               | lea                 esi, [edx + ecx*4]

    condition:
        7 of them and filesize < 65536
}