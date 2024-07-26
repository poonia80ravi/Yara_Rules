rule win_navrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.navrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.navrat"
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
        $sequence_0 = { c745e066745c57 c745e4696e646f c745e877735c43 c745ec75727265 c745f06e745665 c745f47273696f 66c745f86e5c }
            // n = 7, score = 300
            //   c745e066745c57       | mov                 dword ptr [ebp - 0x20], 0x575c7466
            //   c745e4696e646f       | mov                 dword ptr [ebp - 0x1c], 0x6f646e69
            //   c745e877735c43       | mov                 dword ptr [ebp - 0x18], 0x435c7377
            //   c745ec75727265       | mov                 dword ptr [ebp - 0x14], 0x65727275
            //   c745f06e745665       | mov                 dword ptr [ebp - 0x10], 0x6556746e
            //   c745f47273696f       | mov                 dword ptr [ebp - 0xc], 0x6f697372
            //   66c745f86e5c         | mov                 word ptr [ebp - 8], 0x5c6e

        $sequence_1 = { e8???????? 66a1???????? 83c40c 6683f805 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   66a1????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6683f805             | cmp                 ax, 5

        $sequence_2 = { 8b7608 83461c02 5f 5e }
            // n = 4, score = 300
            //   8b7608               | mov                 esi, dword ptr [esi + 8]
            //   83461c02             | add                 dword ptr [esi + 0x1c], 2
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_3 = { c745e4696e646f c745e877735c43 c745ec75727265 c745f06e745665 c745f47273696f }
            // n = 5, score = 300
            //   c745e4696e646f       | mov                 dword ptr [ebp - 0x1c], 0x6f646e69
            //   c745e877735c43       | mov                 dword ptr [ebp - 0x18], 0x435c7377
            //   c745ec75727265       | mov                 dword ptr [ebp - 0x14], 0x65727275
            //   c745f06e745665       | mov                 dword ptr [ebp - 0x10], 0x6556746e
            //   c745f47273696f       | mov                 dword ptr [ebp - 0xc], 0x6f697372

        $sequence_4 = { 3c39 7f0a 3c30 7c06 }
            // n = 4, score = 300
            //   3c39                 | cmp                 al, 0x39
            //   7f0a                 | jg                  0xc
            //   3c30                 | cmp                 al, 0x30
            //   7c06                 | jl                  8

        $sequence_5 = { c745e877735c43 c745ec75727265 c745f06e745665 c745f47273696f 66c745f86e5c }
            // n = 5, score = 300
            //   c745e877735c43       | mov                 dword ptr [ebp - 0x18], 0x435c7377
            //   c745ec75727265       | mov                 dword ptr [ebp - 0x14], 0x65727275
            //   c745f06e745665       | mov                 dword ptr [ebp - 0x10], 0x6556746e
            //   c745f47273696f       | mov                 dword ptr [ebp - 0xc], 0x6f697372
            //   66c745f86e5c         | mov                 word ptr [ebp - 8], 0x5c6e

        $sequence_6 = { 7503 884702 85f6 7407 }
            // n = 4, score = 300
            //   7503                 | jne                 5
            //   884702               | mov                 byte ptr [edi + 2], al
            //   85f6                 | test                esi, esi
            //   7407                 | je                  9

        $sequence_7 = { 7503 884702 85f6 7407 8b7608 }
            // n = 5, score = 300
            //   7503                 | jne                 5
            //   884702               | mov                 byte ptr [edi + 2], al
            //   85f6                 | test                esi, esi
            //   7407                 | je                  9
            //   8b7608               | mov                 esi, dword ptr [esi + 8]

        $sequence_8 = { c745d85c4d6963 c745dc726f736f c745e066745c57 c745e4696e646f c745e877735c43 }
            // n = 5, score = 300
            //   c745d85c4d6963       | mov                 dword ptr [ebp - 0x28], 0x63694d5c
            //   c745dc726f736f       | mov                 dword ptr [ebp - 0x24], 0x6f736f72
            //   c745e066745c57       | mov                 dword ptr [ebp - 0x20], 0x575c7466
            //   c745e4696e646f       | mov                 dword ptr [ebp - 0x1c], 0x6f646e69
            //   c745e877735c43       | mov                 dword ptr [ebp - 0x18], 0x435c7377

        $sequence_9 = { 8d48d0 80f909 7707 0fbec0 83c004 c3 }
            // n = 6, score = 300
            //   8d48d0               | lea                 ecx, [eax - 0x30]
            //   80f909               | cmp                 cl, 9
            //   7707                 | ja                  9
            //   0fbec0               | movsx               eax, al
            //   83c004               | add                 eax, 4
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 352256
}