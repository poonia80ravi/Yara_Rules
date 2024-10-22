rule win_purelocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.purelocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purelocker"
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
        $sequence_0 = { 6819000000 68ffffffff ff742408 ff74242c e8???????? 89c3 3b5c2424 }
            // n = 7, score = 100
            //   6819000000           | push                0x19
            //   68ffffffff           | push                0xffffffff
            //   ff742408             | push                dword ptr [esp + 8]
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   e8????????           |                     
            //   89c3                 | mov                 ebx, eax
            //   3b5c2424             | cmp                 ebx, dword ptr [esp + 0x24]

        $sequence_1 = { 8d15be400110 52 e8???????? 8b542428 52 e8???????? 8d15de480110 }
            // n = 7, score = 100
            //   8d15be400110         | lea                 edx, [0x100140be]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d15de480110         | lea                 edx, [0x100148de]

        $sequence_2 = { e8???????? 8b542414 52 e8???????? 8d1502420110 52 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d1502420110         | lea                 edx, [0x10014202]
            //   52                   | push                edx

        $sequence_3 = { 7511 8d442408 68???????? 50 e8???????? 59 }
            // n = 6, score = 100
            //   7511                 | jne                 0x13
            //   8d442408             | lea                 eax, [esp + 8]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_4 = { 8b5c2470 21db 7405 e9???????? 0fbe9c240c010000 83fb01 }
            // n = 6, score = 100
            //   8b5c2470             | mov                 ebx, dword ptr [esp + 0x70]
            //   21db                 | and                 ebx, ebx
            //   7405                 | je                  7
            //   e9????????           |                     
            //   0fbe9c240c010000     | movsx               ebx, byte ptr [esp + 0x10c]
            //   83fb01               | cmp                 ebx, 1

        $sequence_5 = { 8b5c2468 83c302 53 e8???????? 89842490000000 8b9c2490000000 21db }
            // n = 7, score = 100
            //   8b5c2468             | mov                 ebx, dword ptr [esp + 0x68]
            //   83c302               | add                 ebx, 2
            //   53                   | push                ebx
            //   e8????????           |                     
            //   89842490000000       | mov                 dword ptr [esp + 0x90], eax
            //   8b9c2490000000       | mov                 ebx, dword ptr [esp + 0x90]
            //   21db                 | and                 ebx, ebx

        $sequence_6 = { 8b5c241c 21db 7e07 b801000000 eb02 31c0 21c0 }
            // n = 7, score = 100
            //   8b5c241c             | mov                 ebx, dword ptr [esp + 0x1c]
            //   21db                 | and                 ebx, ebx
            //   7e07                 | jle                 9
            //   b801000000           | mov                 eax, 1
            //   eb02                 | jmp                 4
            //   31c0                 | xor                 eax, eax
            //   21c0                 | and                 eax, eax

        $sequence_7 = { 89c3 21db 7505 e9???????? eb25 8b9c2488000000 21db }
            // n = 7, score = 100
            //   89c3                 | mov                 ebx, eax
            //   21db                 | and                 ebx, ebx
            //   7505                 | jne                 7
            //   e9????????           |                     
            //   eb25                 | jmp                 0x27
            //   8b9c2488000000       | mov                 ebx, dword ptr [esp + 0x88]
            //   21db                 | and                 ebx, ebx

        $sequence_8 = { 3b9c24a8000000 7204 31c0 eb05 b801000000 09c0 0f85fffbffff }
            // n = 7, score = 100
            //   3b9c24a8000000       | cmp                 ebx, dword ptr [esp + 0xa8]
            //   7204                 | jb                  6
            //   31c0                 | xor                 eax, eax
            //   eb05                 | jmp                 7
            //   b801000000           | mov                 eax, 1
            //   09c0                 | or                  eax, eax
            //   0f85fffbffff         | jne                 0xfffffc05

        $sequence_9 = { eb05 b801000000 09c0 0f850efdffff e9???????? c744247401000000 eb00 }
            // n = 7, score = 100
            //   eb05                 | jmp                 7
            //   b801000000           | mov                 eax, 1
            //   09c0                 | or                  eax, eax
            //   0f850efdffff         | jne                 0xfffffd14
            //   e9????????           |                     
            //   c744247401000000     | mov                 dword ptr [esp + 0x74], 1
            //   eb00                 | jmp                 2

    condition:
        7 of them and filesize < 193536
}