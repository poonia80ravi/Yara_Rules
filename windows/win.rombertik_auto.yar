rule win_rombertik_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.rombertik."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rombertik"
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
        $sequence_0 = { ffd7 85c0 741e 8d95dcfdffff }
            // n = 4, score = 200
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   741e                 | je                  0x20
            //   8d95dcfdffff         | lea                 edx, [ebp - 0x224]

        $sequence_1 = { 81ec08010000 b904010000 8bc6 c60000 40 }
            // n = 5, score = 200
            //   81ec08010000         | sub                 esp, 0x108
            //   b904010000           | mov                 ecx, 0x104
            //   8bc6                 | mov                 eax, esi
            //   c60000               | mov                 byte ptr [eax], 0
            //   40                   | inc                 eax

        $sequence_2 = { f3a4 61 8b5df8 8b75f0 8b7df4 }
            // n = 5, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   61                   | popal               
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   8b75f0               | mov                 esi, dword ptr [ebp - 0x10]
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]

        $sequence_3 = { 7e16 60 8b75f8 8b7df4 }
            // n = 4, score = 200
            //   7e16                 | jle                 0x18
            //   60                   | pushal              
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]

        $sequence_4 = { 85ff 741d 85f6 7e19 60 8b750c 8b7df8 }
            // n = 7, score = 200
            //   85ff                 | test                edi, edi
            //   741d                 | je                  0x1f
            //   85f6                 | test                esi, esi
            //   7e19                 | jle                 0x1b
            //   60                   | pushal              
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]

        $sequence_5 = { f3a4 61 8b5dfc 8b35???????? 68???????? 53 ffd6 }
            // n = 7, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   61                   | popal               
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   8b35????????         |                     
            //   68????????           |                     
            //   53                   | push                ebx
            //   ffd6                 | call                esi

        $sequence_6 = { 66894804 8a15???????? 885006 8b4508 8bf0 }
            // n = 5, score = 200
            //   66894804             | mov                 word ptr [eax + 4], cx
            //   8a15????????         |                     
            //   885006               | mov                 byte ptr [eax + 6], dl
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bf0                 | mov                 esi, eax

        $sequence_7 = { 61 8b45fc 8b4d08 c64408ff00 b801000000 5f }
            // n = 6, score = 200
            //   61                   | popal               
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   c64408ff00           | mov                 byte ptr [eax + ecx - 1], 0
            //   b801000000           | mov                 eax, 1
            //   5f                   | pop                 edi

        $sequence_8 = { 8b5d0c 85db 0f84cb000000 837d1400 0f84c1000000 817d18a00f0000 0f87b4000000 }
            // n = 7, score = 200
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   85db                 | test                ebx, ebx
            //   0f84cb000000         | je                  0xd1
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0
            //   0f84c1000000         | je                  0xc7
            //   817d18a00f0000       | cmp                 dword ptr [ebp + 0x18], 0xfa0
            //   0f87b4000000         | ja                  0xba

        $sequence_9 = { 50 52 8d85f4feffff 57 50 e8???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   52                   | push                edx
            //   8d85f4feffff         | lea                 eax, [ebp - 0x10c]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 73728
}