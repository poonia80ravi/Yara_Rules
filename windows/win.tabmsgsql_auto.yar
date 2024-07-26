rule win_tabmsgsql_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.tabmsgsql."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tabmsgsql"
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
        $sequence_0 = { c705????????808d5b00 8b4df4 5f 5e b801000000 64890d00000000 }
            // n = 6, score = 100
            //   c705????????808d5b00     |     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   b801000000           | mov                 eax, 1
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_1 = { b900f40100 33c0 8bfe f3ab 8b442414 50 }
            // n = 6, score = 100
            //   b900f40100           | mov                 ecx, 0x1f400
            //   33c0                 | xor                 eax, eax
            //   8bfe                 | mov                 edi, esi
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   50                   | push                eax

        $sequence_2 = { f7d9 1bc9 81e1000080ff 81c100008000 81c940004004 0bc1 }
            // n = 6, score = 100
            //   f7d9                 | neg                 ecx
            //   1bc9                 | sbb                 ecx, ecx
            //   81e1000080ff         | and                 ecx, 0xff800000
            //   81c100008000         | add                 ecx, 0x800000
            //   81c940004004         | or                  ecx, 0x4400040
            //   0bc1                 | or                  eax, ecx

        $sequence_3 = { 83c410 85c0 7503 5f 5e c3 8d8e5af40100 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8d8e5af40100         | lea                 ecx, [esi + 0x1f45a]

        $sequence_4 = { c1e104 8bc1 4e 99 f7fe 8bc1 895500 }
            // n = 7, score = 100
            //   c1e104               | shl                 ecx, 4
            //   8bc1                 | mov                 eax, ecx
            //   4e                   | dec                 esi
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   8bc1                 | mov                 eax, ecx
            //   895500               | mov                 dword ptr [ebp], edx

        $sequence_5 = { c6440c1400 49 79e4 8d7c2414 83c9ff 33c0 8d9c245c030000 }
            // n = 7, score = 100
            //   c6440c1400           | mov                 byte ptr [esp + ecx + 0x14], 0
            //   49                   | dec                 ecx
            //   79e4                 | jns                 0xffffffe6
            //   8d7c2414             | lea                 edi, [esp + 0x14]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8d9c245c030000       | lea                 ebx, [esp + 0x35c]

        $sequence_6 = { eb05 1bc0 83d8ff 3bc3 0f84ca0c0000 be???????? }
            // n = 6, score = 100
            //   eb05                 | jmp                 7
            //   1bc0                 | sbb                 eax, eax
            //   83d8ff               | sbb                 eax, -1
            //   3bc3                 | cmp                 eax, ebx
            //   0f84ca0c0000         | je                  0xcd0
            //   be????????           |                     

        $sequence_7 = { 50 ff15???????? 8b7c2418 8b1d???????? 83c408 33f6 ffd3 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   8b1d????????         |                     
            //   83c408               | add                 esp, 8
            //   33f6                 | xor                 esi, esi
            //   ffd3                 | call                ebx

        $sequence_8 = { 52 c744243004000000 ffd5 8b442410 8b4e0c 0d80010000 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   c744243004000000     | mov                 dword ptr [esp + 0x30], 4
            //   ffd5                 | call                ebp
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   0d80010000           | or                  eax, 0x180

        $sequence_9 = { 8d85a8feffff 8d8d9cfbffff 8945b0 b804010000 8945b4 894dbc 8945c0 }
            // n = 7, score = 100
            //   8d85a8feffff         | lea                 eax, [ebp - 0x158]
            //   8d8d9cfbffff         | lea                 ecx, [ebp - 0x464]
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   b804010000           | mov                 eax, 0x104
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax
            //   894dbc               | mov                 dword ptr [ebp - 0x44], ecx
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax

    condition:
        7 of them and filesize < 163840
}