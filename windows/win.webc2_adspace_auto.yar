rule win_webc2_adspace_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webc2_adspace."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_adspace"
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
        $sequence_0 = { 83c414 85c0 7408 c744241001000000 bf???????? 57 }
            // n = 6, score = 100
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1
            //   bf????????           |                     
            //   57                   | push                edi

        $sequence_1 = { 33c9 3b442404 0f9dc1 8bc1 c3 c20400 8b442408 }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   3b442404             | cmp                 eax, dword ptr [esp + 4]
            //   0f9dc1               | setge               cl
            //   8bc1                 | mov                 eax, ecx
            //   c3                   | ret                 
            //   c20400               | ret                 4
            //   8b442408             | mov                 eax, dword ptr [esp + 8]

        $sequence_2 = { 83c40c 8bf8 8d45fc 50 }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8bf8                 | mov                 edi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax

        $sequence_3 = { ff750c 894508 50 ff15???????? }
            // n = 4, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 7e21 56 8d85ecfeffff ff7704 50 ffd3 56 }
            // n = 7, score = 100
            //   7e21                 | jle                 0x23
            //   56                   | push                esi
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   ff7704               | push                dword ptr [edi + 4]
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   56                   | push                esi

        $sequence_5 = { 53 ff15???????? 40 50 8d442450 53 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   8d442450             | lea                 eax, [esp + 0x50]
            //   53                   | push                ebx

        $sequence_6 = { ffd6 8bf8 c70424???????? ffd6 59 8bf0 }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   8bf8                 | mov                 edi, eax
            //   c70424????????       |                     
            //   ffd6                 | call                esi
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax

        $sequence_7 = { e8???????? 8bd8 8b44242c 57 8d443005 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   57                   | push                edi
            //   8d443005             | lea                 eax, [eax + esi + 5]
            //   50                   | push                eax

        $sequence_8 = { 83c418 6a01 e8???????? 6a03 e8???????? }
            // n = 5, score = 100
            //   83c418               | add                 esp, 0x18
            //   6a01                 | push                1
            //   e8????????           |                     
            //   6a03                 | push                3
            //   e8????????           |                     

        $sequence_9 = { 8901 8b44240c 894104 58 c20800 }
            // n = 5, score = 100
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   58                   | pop                 eax
            //   c20800               | ret                 8

    condition:
        7 of them and filesize < 49152
}