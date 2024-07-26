rule win_rover_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.rover."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rover"
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
        $sequence_0 = { 33ed 668986ac050000 8d4c2410 51 39ae74020000 7463 }
            // n = 6, score = 100
            //   33ed                 | xor                 ebp, ebp
            //   668986ac050000       | mov                 word ptr [esi + 0x5ac], ax
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   51                   | push                ecx
            //   39ae74020000         | cmp                 dword ptr [esi + 0x274], ebp
            //   7463                 | je                  0x65

        $sequence_1 = { eb0a c780e0020000284b4400 8b88e0020000 5e 89442404 8b5104 ffe2 }
            // n = 7, score = 100
            //   eb0a                 | jmp                 0xc
            //   c780e0020000284b4400     | mov    dword ptr [eax + 0x2e0], 0x444b28
            //   8b88e0020000         | mov                 ecx, dword ptr [eax + 0x2e0]
            //   5e                   | pop                 esi
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   ffe2                 | jmp                 edx

        $sequence_2 = { 8b7c2424 8d4c2444 51 52 57 89742450 ff54243c }
            // n = 7, score = 100
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]
            //   8d4c2444             | lea                 ecx, [esp + 0x44]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   57                   | push                edi
            //   89742450             | mov                 dword ptr [esp + 0x50], esi
            //   ff54243c             | call                dword ptr [esp + 0x3c]

        $sequence_3 = { 89742418 8b7c242c 8d4704 50 }
            // n = 4, score = 100
            //   89742418             | mov                 dword ptr [esp + 0x18], esi
            //   8b7c242c             | mov                 edi, dword ptr [esp + 0x2c]
            //   8d4704               | lea                 eax, [edi + 4]
            //   50                   | push                eax

        $sequence_4 = { 750a 68???????? e9???????? 83fe48 750f 68???????? 8d542408 }
            // n = 7, score = 100
            //   750a                 | jne                 0xc
            //   68????????           |                     
            //   e9????????           |                     
            //   83fe48               | cmp                 esi, 0x48
            //   750f                 | jne                 0x11
            //   68????????           |                     
            //   8d542408             | lea                 edx, [esp + 8]

        $sequence_5 = { 83c474 50 c68424ec0b000007 ffd5 83c408 8d8c24d8000000 8ad8 }
            // n = 7, score = 100
            //   83c474               | add                 esp, 0x74
            //   50                   | push                eax
            //   c68424ec0b000007     | mov                 byte ptr [esp + 0xbec], 7
            //   ffd5                 | call                ebp
            //   83c408               | add                 esp, 8
            //   8d8c24d8000000       | lea                 ecx, [esp + 0xd8]
            //   8ad8                 | mov                 bl, al

        $sequence_6 = { e8???????? 83c410 2bf8 7404 85ff 7d1b 68???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   2bf8                 | sub                 edi, eax
            //   7404                 | je                  6
            //   85ff                 | test                edi, edi
            //   7d1b                 | jge                 0x1d
            //   68????????           |                     

        $sequence_7 = { 50 c684245c02000019 ff15???????? 83c408 8bcf 8ad8 c684245402000018 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c684245c02000019     | mov                 byte ptr [esp + 0x25c], 0x19
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8
            //   8bcf                 | mov                 ecx, edi
            //   8ad8                 | mov                 bl, al
            //   c684245402000018     | mov                 byte ptr [esp + 0x254], 0x18

        $sequence_8 = { 8b87a8030000 85c0 7414 50 ff15???????? 83c404 8986c4050000 }
            // n = 7, score = 100
            //   8b87a8030000         | mov                 eax, dword ptr [edi + 0x3a8]
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   8986c4050000         | mov                 dword ptr [esi + 0x5c4], eax

        $sequence_9 = { d1fa 2bda 53 57 50 }
            // n = 5, score = 100
            //   d1fa                 | sar                 edx, 1
            //   2bda                 | sub                 ebx, edx
            //   53                   | push                ebx
            //   57                   | push                edi
            //   50                   | push                eax

    condition:
        7 of them and filesize < 704512
}