rule win_hookinjex_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hookinjex."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hookinjex"
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
        $sequence_0 = { e8???????? 833d????????00 7411 b906000000 e8???????? 488905???????? c705????????01000000 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7411                 | mov                 eax, 0x20a
            //   b906000000           | jmp                 9
            //   e8????????           |                     
            //   488905????????       |                     
            //   c705????????01000000     |     

        $sequence_1 = { e8???????? b90c000000 8908 8bc1 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   b90c000000           | cmp                 dword ptr [esp + 0x38], 0x1000
            //   8908                 | jb                  0xfb
            //   8bc1                 | dec                 eax

        $sequence_2 = { e8???????? 85c0 751f 33d2 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   751f                 | inc                 ebx
            //   33d2                 | mov                 ecx, 0xc

        $sequence_3 = { e8???????? b80a020000 eb02 33c0 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   b80a020000           | jb                  0x2e2
            //   eb02                 | dec                 eax
            //   33c0                 | mov                 eax, dword ptr [esp + 0x60]

        $sequence_4 = { e8???????? 85c0 740f b907b60000 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   85c0                 | je                  0xc
            //   740f                 | cmp                 byte ptr [ebx], 0
            //   b907b60000           | je                  8

        $sequence_5 = { e8???????? 488bc8 e8???????? 83f805 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   488bc8               | xor                 eax, eax
            //   e8????????           |                     
            //   83f805               | test                eax, eax

        $sequence_6 = { e8???????? 833d????????00 7411 b903000000 e8???????? 488905???????? }
            // n = 6, score = 300
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7411                 | dec                 eax
            //   b903000000           | inc                 ebx
            //   e8????????           |                     
            //   488905????????       |                     

        $sequence_7 = { e8???????? 85c0 7408 803b00 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   85c0                 | and                 eax, 0x1f
            //   7408                 | dec                 eax
            //   803b00               | cmp                 dword ptr [esp + 0x30], 0x1000

        $sequence_8 = { 48817c243000100000 0f82dc020000 488b442460 4889442438 }
            // n = 4, score = 200
            //   48817c243000100000     | dec    eax
            //   0f82dc020000         | cmp                 dword ptr [esp + 0x30], 0x1000
            //   488b442460           | jb                  0x2e2
            //   4889442438           | dec                 eax

        $sequence_9 = { 25001b0000 3d00100000 750a c744244401000000 }
            // n = 4, score = 200
            //   25001b0000           | and                 eax, 0x1b00
            //   3d00100000           | cmp                 eax, 0x1000
            //   750a                 | jne                 0xc
            //   c744244401000000     | mov                 dword ptr [esp + 0x44], 1

        $sequence_10 = { 2500180000 3d00080000 750d c784245c01000001000000 eb0b }
            // n = 5, score = 200
            //   2500180000           | and                 eax, 0x1800
            //   3d00080000           | cmp                 eax, 0x800
            //   750d                 | jne                 0xf
            //   c784245c01000001000000     | mov    dword ptr [esp + 0x15c], 1
            //   eb0b                 | jmp                 0xd

        $sequence_11 = { 25001b0000 3d00100000 750d c784242401000001000000 }
            // n = 4, score = 200
            //   25001b0000           | and                 eax, 0x1b00
            //   3d00100000           | cmp                 eax, 0x1000
            //   750d                 | jne                 0xf
            //   c784242401000001000000     | mov    dword ptr [esp + 0x124], 1

        $sequence_12 = { 2500180000 3d00180000 750a c744247c01000000 }
            // n = 4, score = 200
            //   2500180000           | and                 eax, 0x1800
            //   3d00180000           | cmp                 eax, 0x1800
            //   750a                 | jne                 0xc
            //   c744247c01000000     | mov                 dword ptr [esp + 0x7c], 1

        $sequence_13 = { 25001b0000 3d00110000 750a c744245c01000000 }
            // n = 4, score = 200
            //   25001b0000           | and                 eax, 0x1b00
            //   3d00110000           | cmp                 eax, 0x1100
            //   750a                 | jne                 0xc
            //   c744245c01000000     | mov                 dword ptr [esp + 0x5c], 1

        $sequence_14 = { 25001b0000 3d00120000 750a c744246401000000 }
            // n = 4, score = 200
            //   25001b0000           | and                 eax, 0x1b00
            //   3d00120000           | cmp                 eax, 0x1200
            //   750a                 | jne                 0xc
            //   c744246401000000     | mov                 dword ptr [esp + 0x64], 1

        $sequence_15 = { 25001b0000 3d00110000 750d c784243c01000001000000 }
            // n = 4, score = 200
            //   25001b0000           | and                 eax, 0x1b00
            //   3d00110000           | cmp                 eax, 0x1100
            //   750d                 | jne                 0xf
            //   c784243c01000001000000     | mov    dword ptr [esp + 0x13c], 1

    condition:
        7 of them and filesize < 6545408
}