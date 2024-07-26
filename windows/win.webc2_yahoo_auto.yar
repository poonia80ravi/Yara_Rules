rule win_webc2_yahoo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webc2_yahoo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_yahoo"
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
        $sequence_0 = { 57 6a40 ff15???????? 8945fc a0???????? 8885d8d7ffff }
            // n = 6, score = 100
            //   57                   | push                edi
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   a0????????           |                     
            //   8885d8d7ffff         | mov                 byte ptr [ebp - 0x2828], al

        $sequence_1 = { 7451 ff45fc 395dfc 76d8 68???????? ff750c ff15???????? }
            // n = 7, score = 100
            //   7451                 | je                  0x53
            //   ff45fc               | inc                 dword ptr [ebp - 4]
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   76d8                 | jbe                 0xffffffda
            //   68????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     

        $sequence_2 = { 33ff 48 c7459c44000000 897dfc 0f84d7010000 48 }
            // n = 6, score = 100
            //   33ff                 | xor                 edi, edi
            //   48                   | dec                 eax
            //   c7459c44000000       | mov                 dword ptr [ebp - 0x64], 0x44
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   0f84d7010000         | je                  0x1dd
            //   48                   | dec                 eax

        $sequence_3 = { 68???????? e8???????? 83c410 3bc7 894508 }
            // n = 5, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   3bc7                 | cmp                 eax, edi
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_4 = { 8b450c 8365fc00 53 56 48 57 48 }
            // n = 7, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   48                   | dec                 eax
            //   57                   | push                edi
            //   48                   | dec                 eax

        $sequence_5 = { 50 ff15???????? 8b1d???????? 8d852cffffff 50 ffd3 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   8d852cffffff         | lea                 eax, [ebp - 0xd4]
            //   50                   | push                eax
            //   ffd3                 | call                ebx

        $sequence_6 = { 50 8d4314 56 50 56 57 8bcb }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d4314               | lea                 eax, [ebx + 0x14]
            //   56                   | push                esi
            //   50                   | push                eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bcb                 | mov                 ecx, ebx

        $sequence_7 = { e8???????? 59 85c0 59 7418 8d4590 68???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   7418                 | je                  0x1a
            //   8d4590               | lea                 eax, [ebp - 0x70]
            //   68????????           |                     

        $sequence_8 = { 8b7518 83c414 8d85fcd7ffff 8bcb }
            // n = 4, score = 100
            //   8b7518               | mov                 esi, dword ptr [ebp + 0x18]
            //   83c414               | add                 esp, 0x14
            //   8d85fcd7ffff         | lea                 eax, [ebp - 0x2804]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_9 = { ff742410 ffb69c841e00 ff15???????? 85c0 6a64 }
            // n = 5, score = 100
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ffb69c841e00         | push                dword ptr [esi + 0x1e849c]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   6a64                 | push                0x64

    condition:
        7 of them and filesize < 8060928
}