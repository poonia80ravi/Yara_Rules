rule win_radrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.radrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.radrat"
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
        $sequence_0 = { e8???????? 8b55e0 c702???????? 8b45e0 c6400400 c745fcffffffff 8b45e0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   c702????????         |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   c6400400             | mov                 byte ptr [eax + 4], 0
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_1 = { 8b8d9cfeffff e8???????? c645fc09 8b8d9cfeffff 83c128 898d98feffff 8b8d98feffff }
            // n = 7, score = 100
            //   8b8d9cfeffff         | mov                 ecx, dword ptr [ebp - 0x164]
            //   e8????????           |                     
            //   c645fc09             | mov                 byte ptr [ebp - 4], 9
            //   8b8d9cfeffff         | mov                 ecx, dword ptr [ebp - 0x164]
            //   83c128               | add                 ecx, 0x28
            //   898d98feffff         | mov                 dword ptr [ebp - 0x168], ecx
            //   8b8d98feffff         | mov                 ecx, dword ptr [ebp - 0x168]

        $sequence_2 = { c645fc01 8d8d60ffffff e8???????? c645fc00 8d4d88 e8???????? c78530ffffff00000000 }
            // n = 7, score = 100
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   e8????????           |                     
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8d4d88               | lea                 ecx, [ebp - 0x78]
            //   e8????????           |                     
            //   c78530ffffff00000000     | mov    dword ptr [ebp - 0xd0], 0

        $sequence_3 = { c745fcffffffff 8d4dcc e8???????? 8a8564fcffff e9???????? 8d8dd0feffff e8???????? }
            // n = 7, score = 100
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   e8????????           |                     
            //   8a8564fcffff         | mov                 al, byte ptr [ebp - 0x39c]
            //   e9????????           |                     
            //   8d8dd0feffff         | lea                 ecx, [ebp - 0x130]
            //   e8????????           |                     

        $sequence_4 = { e8???????? 8b4db8 8b55b4 8b82a0010000 8981ac000000 8b4db4 81c1d8010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]
            //   8b82a0010000         | mov                 eax, dword ptr [edx + 0x1a0]
            //   8981ac000000         | mov                 dword ptr [ecx + 0xac], eax
            //   8b4db4               | mov                 ecx, dword ptr [ebp - 0x4c]
            //   81c1d8010000         | add                 ecx, 0x1d8

        $sequence_5 = { e9???????? 817da800010000 760c c785f0fdffff00010000 eb09 8b45a8 8985f0fdffff }
            // n = 7, score = 100
            //   e9????????           |                     
            //   817da800010000       | cmp                 dword ptr [ebp - 0x58], 0x100
            //   760c                 | jbe                 0xe
            //   c785f0fdffff00010000     | mov    dword ptr [ebp - 0x210], 0x100
            //   eb09                 | jmp                 0xb
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   8985f0fdffff         | mov                 dword ptr [ebp - 0x210], eax

        $sequence_6 = { c645fc06 6a00 8b951cfeffff 8b4218 83c001 50 8b8d1cfeffff }
            // n = 7, score = 100
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6
            //   6a00                 | push                0
            //   8b951cfeffff         | mov                 edx, dword ptr [ebp - 0x1e4]
            //   8b4218               | mov                 eax, dword ptr [edx + 0x18]
            //   83c001               | add                 eax, 1
            //   50                   | push                eax
            //   8b8d1cfeffff         | mov                 ecx, dword ptr [ebp - 0x1e4]

        $sequence_7 = { e8???????? 25ff000000 85c0 755d c6858c99ffff01 c645fc8b 8d8dd0dfffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   25ff000000           | and                 eax, 0xff
            //   85c0                 | test                eax, eax
            //   755d                 | jne                 0x5f
            //   c6858c99ffff01       | mov                 byte ptr [ebp - 0x6674], 1
            //   c645fc8b             | mov                 byte ptr [ebp - 4], 0x8b
            //   8d8dd0dfffff         | lea                 ecx, [ebp - 0x2030]

        $sequence_8 = { e8???????? 8a8568ffffff e9???????? 8d8d78ffffff e8???????? c645fc03 8d4da0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8a8568ffffff         | mov                 al, byte ptr [ebp - 0x98]
            //   e9????????           |                     
            //   8d8d78ffffff         | lea                 ecx, [ebp - 0x88]
            //   e8????????           |                     
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d4da0               | lea                 ecx, [ebp - 0x60]

        $sequence_9 = { 8d8d40f8ffff e8???????? c3 8d8d18f8ffff e8???????? c3 8d8df0f7ffff }
            // n = 7, score = 100
            //   8d8d40f8ffff         | lea                 ecx, [ebp - 0x7c0]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d8d18f8ffff         | lea                 ecx, [ebp - 0x7e8]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d8df0f7ffff         | lea                 ecx, [ebp - 0x810]

    condition:
        7 of them and filesize < 2080768
}