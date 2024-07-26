rule win_hardrain_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hardrain."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hardrain"
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
        $sequence_0 = { 7e22 8b7108 8bfa 8b510c 8b4110 0bf2 897108 }
            // n = 7, score = 200
            //   7e22                 | jle                 0x24
            //   8b7108               | mov                 esi, dword ptr [ecx + 8]
            //   8bfa                 | mov                 edi, edx
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]
            //   8b4110               | mov                 eax, dword ptr [ecx + 0x10]
            //   0bf2                 | or                  esi, edx
            //   897108               | mov                 dword ptr [ecx + 8], esi

        $sequence_1 = { 8b442434 6a0c 51 56 }
            // n = 4, score = 200
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   6a0c                 | push                0xc
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_2 = { 6689442409 52 ff15???????? 8b4c2418 668944240b }
            // n = 5, score = 200
            //   6689442409           | mov                 word ptr [esp + 9], ax
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   668944240b           | mov                 word ptr [esp + 0xb], ax

        $sequence_3 = { 8bc6 8bfa be03000000 99 f7fe be7856b4c2 }
            // n = 6, score = 200
            //   8bc6                 | mov                 eax, esi
            //   8bfa                 | mov                 edi, edx
            //   be03000000           | mov                 esi, 3
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   be7856b4c2           | mov                 esi, 0xc2b45678

        $sequence_4 = { 8b4110 0bf2 897108 8bf0 0bf2 89710c }
            // n = 6, score = 200
            //   8b4110               | mov                 eax, dword ptr [ecx + 0x10]
            //   0bf2                 | or                  esi, edx
            //   897108               | mov                 dword ptr [ecx + 8], esi
            //   8bf0                 | mov                 esi, eax
            //   0bf2                 | or                  esi, edx
            //   89710c               | mov                 dword ptr [ecx + 0xc], esi

        $sequence_5 = { 52 51 e8???????? 83c40c 8b842414010000 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b842414010000       | mov                 eax, dword ptr [esp + 0x114]

        $sequence_6 = { 56 e8???????? 83c408 68???????? ff15???????? 8b442404 50 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   50                   | push                eax

        $sequence_7 = { 6a01 6a04 68???????? 56 e8???????? 83c414 }
            // n = 6, score = 200
            //   6a01                 | push                1
            //   6a04                 | push                4
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_8 = { ff15???????? 68e8030000 8bf0 ff15???????? 85f6 0f8465ffffff }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   68e8030000           | push                0x3e8
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   85f6                 | test                esi, esi
            //   0f8465ffffff         | je                  0xffffff6b

        $sequence_9 = { 6689442422 ff15???????? 8bf0 83feff 0f8493000000 8d442408 50 }
            // n = 7, score = 200
            //   6689442422           | mov                 word ptr [esp + 0x22], ax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   0f8493000000         | je                  0x99
            //   8d442408             | lea                 eax, [esp + 8]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 368640
}