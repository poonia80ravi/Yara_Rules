rule win_evilgrab_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.evilgrab."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilgrab"
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
        $sequence_0 = { 83e103 f3a4 8bca 51 50 8b9524cfffff 52 }
            // n = 7, score = 200
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8b9524cfffff         | mov                 edx, dword ptr [ebp - 0x30dc]
            //   52                   | push                edx

        $sequence_1 = { 83c438 c21400 55 8b6c2440 56 6a00 6a00 }
            // n = 7, score = 200
            //   83c438               | add                 esp, 0x38
            //   c21400               | ret                 0x14
            //   55                   | push                ebp
            //   8b6c2440             | mov                 ebp, dword ptr [esp + 0x40]
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_2 = { 33ff 8b730c 89b5b4a3ffff 89b5b8a3ffff 3bf7 7410 }
            // n = 6, score = 200
            //   33ff                 | xor                 edi, edi
            //   8b730c               | mov                 esi, dword ptr [ebx + 0xc]
            //   89b5b4a3ffff         | mov                 dword ptr [ebp - 0x5c4c], esi
            //   89b5b8a3ffff         | mov                 dword ptr [ebp - 0x5c48], esi
            //   3bf7                 | cmp                 esi, edi
            //   7410                 | je                  0x12

        $sequence_3 = { 8bf0 89b544a4ffff 83feff 0f8459020000 8d9554a4ffff 52 8d855ca4ffff }
            // n = 7, score = 200
            //   8bf0                 | mov                 esi, eax
            //   89b544a4ffff         | mov                 dword ptr [ebp - 0x5bbc], esi
            //   83feff               | cmp                 esi, -1
            //   0f8459020000         | je                  0x25f
            //   8d9554a4ffff         | lea                 edx, [ebp - 0x5bac]
            //   52                   | push                edx
            //   8d855ca4ffff         | lea                 eax, [ebp - 0x5ba4]

        $sequence_4 = { 894dfc 894dec 8b7d14 8b5d10 8b7508 3b4d0c }
            // n = 6, score = 200
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8b7d14               | mov                 edi, dword ptr [ebp + 0x14]
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   3b4d0c               | cmp                 ecx, dword ptr [ebp + 0xc]

        $sequence_5 = { 3bf7 7406 8b16 56 ff5208 8b4c240c 5f }
            // n = 7, score = 200
            //   3bf7                 | cmp                 esi, edi
            //   7406                 | je                  8
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   56                   | push                esi
            //   ff5208               | call                dword ptr [edx + 8]
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   5f                   | pop                 edi

        $sequence_6 = { 6a03 6a00 6a07 6800000080 8bd9 50 ff15???????? }
            // n = 7, score = 200
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a07                 | push                7
            //   6800000080           | push                0x80000000
            //   8bd9                 | mov                 ebx, ecx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { 8b7de4 8b45e8 8d4b04 3bf1 7346 6a00 }
            // n = 6, score = 200
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8d4b04               | lea                 ecx, [ebx + 4]
            //   3bf1                 | cmp                 esi, ecx
            //   7346                 | jae                 0x48
            //   6a00                 | push                0

        $sequence_8 = { 6a64 ff15???????? e9???????? 8bcb e8???????? 8d8d60feffff 51 }
            // n = 7, score = 200
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   e9????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8d8d60feffff         | lea                 ecx, [ebp - 0x1a0]
            //   51                   | push                ecx

        $sequence_9 = { ffd5 83c408 8d542444 8d842479060000 52 50 }
            // n = 6, score = 200
            //   ffd5                 | call                ebp
            //   83c408               | add                 esp, 8
            //   8d542444             | lea                 edx, [esp + 0x44]
            //   8d842479060000       | lea                 eax, [esp + 0x679]
            //   52                   | push                edx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 327680
}