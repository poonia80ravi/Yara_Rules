rule win_flagpro_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.flagpro."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flagpro"
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
        $sequence_0 = { 8b5108 50 ffd2 8d44241c e8???????? 8d442420 e8???????? }
            // n = 7, score = 100
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   50                   | push                eax
            //   ffd2                 | call                edx
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   e8????????           |                     
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   e8????????           |                     

        $sequence_1 = { ffd2 8d7c2440 e8???????? 8d442444 e8???????? }
            // n = 5, score = 100
            //   ffd2                 | call                edx
            //   8d7c2440             | lea                 edi, [esp + 0x40]
            //   e8????????           |                     
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   e8????????           |                     

        $sequence_2 = { 8d4c2454 51 51 51 8bf0 8b442428 8b10 }
            // n = 7, score = 100
            //   8d4c2454             | lea                 ecx, [esp + 0x54]
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8bf0                 | mov                 esi, eax
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_3 = { 52 50 8b4120 ffd0 3bc3 7d2d 8b44241c }
            // n = 7, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b4120               | mov                 eax, dword ptr [ecx + 0x20]
            //   ffd0                 | call                eax
            //   3bc3                 | cmp                 eax, ebx
            //   7d2d                 | jge                 0x2f
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]

        $sequence_4 = { 8975f4 f6c203 7441 8b55fc 8b75fc c1fa05 8b1495c0cf4500 }
            // n = 7, score = 100
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   f6c203               | test                dl, 3
            //   7441                 | je                  0x43
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   c1fa05               | sar                 edx, 5
            //   8b1495c0cf4500       | mov                 edx, dword ptr [edx*4 + 0x45cfc0]

        $sequence_5 = { 033485c0cf4500 8b45e4 8b00 8906 }
            // n = 4, score = 100
            //   033485c0cf4500       | add                 esi, dword ptr [eax*4 + 0x45cfc0]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_6 = { e8???????? 6aff 6a00 50 8d4c2468 c68424a445010011 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8d4c2468             | lea                 ecx, [esp + 0x68]
            //   c68424a445010011     | mov                 byte ptr [esp + 0x145a4], 0x11
            //   e8????????           |                     

        $sequence_7 = { ffd3 8d8c2474010000 51 56 }
            // n = 4, score = 100
            //   ffd3                 | call                ebx
            //   8d8c2474010000       | lea                 ecx, [esp + 0x174]
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_8 = { 7305 e8???????? 40 3bf8 0f8312010000 }
            // n = 5, score = 100
            //   7305                 | jae                 7
            //   e8????????           |                     
            //   40                   | inc                 eax
            //   3bf8                 | cmp                 edi, eax
            //   0f8312010000         | jae                 0x118

        $sequence_9 = { 85c0 0f84a9010000 33db 395c2414 0f8692010000 8b2d???????? 8b542410 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f84a9010000         | je                  0x1af
            //   33db                 | xor                 ebx, ebx
            //   395c2414             | cmp                 dword ptr [esp + 0x14], ebx
            //   0f8692010000         | jbe                 0x198
            //   8b2d????????         |                     
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

    condition:
        7 of them and filesize < 1411072
}