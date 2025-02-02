rule win_maggie_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.maggie."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maggie"
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
        $sequence_0 = { c744243401000000 eb08 c744243400000000 488b4c2450 8b442434 8b4908 }
            // n = 6, score = 100
            //   c744243401000000     | dec                 eax
            //   eb08                 | mov                 edi, ecx
            //   c744243400000000     | dec                 eax
            //   488b4c2450           | test                edx, edx
            //   8b442434             | jne                 0x156e
            //   8b4908               | dec                 eax

        $sequence_1 = { 488d0523e40200 4889442450 488d050be40200 33db 4889442458 bd03000000 488d05f0e30200 }
            // n = 7, score = 100
            //   488d0523e40200       | lea                 edx, [edi + 0x90]
            //   4889442450           | inc                 esp
            //   488d050be40200       | mov                 byte ptr [eax], ah
            //   33db                 | dec                 eax
            //   4889442458           | mov                 eax, dword ptr [edi + 0x20]
            //   bd03000000           | dec                 esp
            //   488d05f0e30200       | lea                 ecx, [esp + 0xa0]

        $sequence_2 = { c644244131 894120 0fb605???????? c644244232 884124 33c0 4883c9ff }
            // n = 7, score = 100
            //   c644244131           | jmp                 0x58b
            //   894120               | dec                 eax
            //   0fb605????????       |                     
            //   c644244232           | lea                 edx, [0x2b2a0]
            //   884124               | jmp                 0x5a6
            //   33c0                 | dec                 eax
            //   4883c9ff             | lea                 edi, [0x2044d]

        $sequence_3 = { 448b4c2448 488d442448 4c8bc3 ba04000000 488bcf 4889442420 ff15???????? }
            // n = 7, score = 100
            //   448b4c2448           | mov                 ecx, eax
            //   488d442448           | dec                 eax
            //   4c8bc3               | lea                 ecx, [0x29fe5]
            //   ba04000000           | dec                 eax
            //   488bcf               | mov                 ecx, ebp
            //   4889442420           | dec                 eax
            //   ff15????????         |                     

        $sequence_4 = { 83c001 89442450 8b442450 4883f808 7202 eb18 488b8c2488000000 }
            // n = 7, score = 100
            //   83c001               | dec                 eax
            //   89442450             | lea                 ecx, [esp + 0x50]
            //   8b442450             | inc                 ecx
            //   4883f808             | mov                 esi, 1
            //   7202                 | mov                 edx, 0xfe
            //   eb18                 | dec                 eax
            //   488b8c2488000000     | lea                 edx, [esp + 0x78]

        $sequence_5 = { 488d0df1ac0200 e8???????? b001 4883c438 c3 ff15???????? }
            // n = 6, score = 100
            //   488d0df1ac0200       | cmp                 esi, edx
            //   e8????????           |                     
            //   b001                 | mov                 ecx, edx
            //   4883c438             | shr                 ecx, 0x1f
            //   c3                   | add                 edx, ecx
            //   ff15????????         |                     

        $sequence_6 = { 488b4320 488b4b08 48898398000000 8b432c 4c8d4c2468 83c00a 448d4601 }
            // n = 7, score = 100
            //   488b4320             | test                al, al
            //   488b4b08             | jne                 0x66e
            //   48898398000000       | dec                 eax
            //   8b432c               | lea                 eax, [esp + 0x30]
            //   4c8d4c2468           | dec                 eax
            //   83c00a               | lea                 edx, [esp + 0x50]
            //   448d4601             | dec                 eax

        $sequence_7 = { 488bd0 e8???????? 4883c9ff 33c0 488d7c2458 f2ae 48f7d1 }
            // n = 7, score = 100
            //   488bd0               | dec                 eax
            //   e8????????           |                     
            //   4883c9ff             | lea                 ecx, [esp + 0x430]
            //   33c0                 | mov                 edx, 0x1fe
            //   488d7c2458           | dec                 eax
            //   f2ae                 | mov                 ecx, dword ptr [esp + 0x58]
            //   48f7d1               | xor                 eax, eax

        $sequence_8 = { 4c8d842480010000 488d1524610200 488bce e8???????? 488d542440 488bcb ff15???????? }
            // n = 7, score = 100
            //   4c8d842480010000     | jne                 0x316
            //   488d1524610200       | cmp                 edi, 0x100
            //   488bce               | jge                 0x333
            //   e8????????           |                     
            //   488d542440           | dec                 eax
            //   488bcb               | arpl                di, cx
            //   ff15????????         |                     

        $sequence_9 = { 4c8d056e080200 488d8c24b0020000 bafe000000 e8???????? eb32 4c8d05bb050200 488d8c24b0010000 }
            // n = 7, score = 100
            //   4c8d056e080200       | mov                 eax, dword ptr [esp + 0x28]
            //   488d8c24b0020000     | dec                 eax
            //   bafe000000           | mov                 edx, dword ptr [esp + 0x20]
            //   e8????????           |                     
            //   eb32                 | dec                 eax
            //   4c8d05bb050200       | mov                 ecx, edi
            //   488d8c24b0010000     | jne                 0x198

    condition:
        7 of them and filesize < 611328
}