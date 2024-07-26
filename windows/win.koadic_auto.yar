rule win_koadic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.koadic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.koadic"
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
        $sequence_0 = { 8d0c24 e8???????? 8d542404 52 6800000000 6805000000 6804000000 }
            // n = 7, score = 100
            //   8d0c24               | lea                 ecx, [esp]
            //   e8????????           |                     
            //   8d542404             | lea                 edx, [esp + 4]
            //   52                   | push                edx
            //   6800000000           | push                0
            //   6805000000           | push                5
            //   6804000000           | push                4

        $sequence_1 = { 894708 8b45f0 89470c 53 8d45fc 50 }
            // n = 6, score = 100
            //   894708               | mov                 dword ptr [edi + 8], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   89470c               | mov                 dword ptr [edi + 0xc], eax
            //   53                   | push                ebx
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax

        $sequence_2 = { 8bc3 3bdd 75ee 5b }
            // n = 4, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   3bdd                 | cmp                 ebx, ebp
            //   75ee                 | jne                 0xfffffff0
            //   5b                   | pop                 ebx

        $sequence_3 = { 8d442408 50 e8???????? e8???????? e8???????? ff35???????? }
            // n = 6, score = 100
            //   8d442408             | lea                 eax, [esp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   ff35????????         |                     

        $sequence_4 = { 81e3fffffcde 0bd9 c745fc80000000 ff75fc 8b4d14 50 8945e4 }
            // n = 7, score = 100
            //   81e3fffffcde         | and                 ebx, 0xdefcffff
            //   0bd9                 | or                  ebx, ecx
            //   c745fc80000000       | mov                 dword ptr [ebp - 4], 0x80
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   50                   | push                eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_5 = { eb54 6a08 50 845c2424 7411 8d4c2418 51 }
            // n = 7, score = 100
            //   eb54                 | jmp                 0x56
            //   6a08                 | push                8
            //   50                   | push                eax
            //   845c2424             | test                byte ptr [esp + 0x24], bl
            //   7411                 | je                  0x13
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx

        $sequence_6 = { 8b7508 57 ff36 33ff 33db ff15???????? 53 }
            // n = 7, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   ff36                 | push                dword ptr [esi]
            //   33ff                 | xor                 edi, edi
            //   33db                 | xor                 ebx, ebx
            //   ff15????????         |                     
            //   53                   | push                ebx

        $sequence_7 = { 755d bea4000000 56 6a00 57 c705????????01000000 }
            // n = 6, score = 100
            //   755d                 | jne                 0x5f
            //   bea4000000           | mov                 esi, 0xa4
            //   56                   | push                esi
            //   6a00                 | push                0
            //   57                   | push                edi
            //   c705????????01000000     |     

        $sequence_8 = { 8d45e4 50 ff37 8955f0 ffd6 837dfc12 }
            // n = 6, score = 100
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   ff37                 | push                dword ptr [edi]
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   ffd6                 | call                esi
            //   837dfc12             | cmp                 dword ptr [ebp - 4], 0x12

        $sequence_9 = { 894508 8b460c 893c81 ff460c 53 ff75ec ff36 }
            // n = 7, score = 100
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   893c81               | mov                 dword ptr [ecx + eax*4], edi
            //   ff460c               | inc                 dword ptr [esi + 0xc]
            //   53                   | push                ebx
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff36                 | push                dword ptr [esi]

    condition:
        7 of them and filesize < 180224
}