rule win_felismus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.felismus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.felismus"
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
        $sequence_0 = { f7d1 0bc8 33ce 03cf 8d9c0b144301a3 8b4c2450 8bfb }
            // n = 7, score = 100
            //   f7d1                 | not                 ecx
            //   0bc8                 | or                  ecx, eax
            //   33ce                 | xor                 ecx, esi
            //   03cf                 | add                 ecx, edi
            //   8d9c0b144301a3       | lea                 ebx, [ebx + ecx - 0x5cfebcec]
            //   8b4c2450             | mov                 ecx, dword ptr [esp + 0x50]
            //   8bfb                 | mov                 edi, ebx

        $sequence_1 = { 68???????? 68???????? f3ab 53 ff15???????? 6a00 6a64 }
            // n = 7, score = 100
            //   68????????           |                     
            //   68????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a64                 | push                0x64

        $sequence_2 = { 56 ffd5 8d442424 50 ff15???????? 6a00 6880000000 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ffd5                 | call                ebp
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6880000000           | push                0x80

        $sequence_3 = { ffd7 85c0 74e9 68???????? 53 ffd5 }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   74e9                 | je                  0xffffffeb
            //   68????????           |                     
            //   53                   | push                ebx
            //   ffd5                 | call                ebp

        $sequence_4 = { 68???????? 56 ff15???????? 83c408 8945c8 85c0 0f841b010000 }
            // n = 7, score = 100
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   85c0                 | test                eax, eax
            //   0f841b010000         | je                  0x121

        $sequence_5 = { c684241401000000 f3ab 66ab aa b9ff000000 33c0 8dbc2415010000 }
            // n = 7, score = 100
            //   c684241401000000     | mov                 byte ptr [esp + 0x114], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b9ff000000           | mov                 ecx, 0xff
            //   33c0                 | xor                 eax, eax
            //   8dbc2415010000       | lea                 edi, [esp + 0x115]

        $sequence_6 = { 83c408 83c8ff 5d 5f 5e 5b }
            // n = 6, score = 100
            //   83c408               | add                 esp, 8
            //   83c8ff               | or                  eax, 0xffffffff
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { 8b4de8 51 ff15???????? 8b5dec e9???????? 53 e8???????? }
            // n = 7, score = 100
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   e9????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_8 = { 5d 5b c3 51 8b4c2408 8d442400 55 }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   51                   | push                ecx
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8d442400             | lea                 eax, [esp]
            //   55                   | push                ebp

        $sequence_9 = { 8d45d4 8d8d7cffffff 8955dc 50 51 52 52 }
            // n = 7, score = 100
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   8d8d7cffffff         | lea                 ecx, [ebp - 0x84]
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   52                   | push                edx

    condition:
        7 of them and filesize < 204800
}