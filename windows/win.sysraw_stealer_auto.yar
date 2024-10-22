rule win_sysraw_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sysraw_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysraw_stealer"
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
        $sequence_0 = { 897dec 897de8 ff15???????? 8b35???????? }
            // n = 4, score = 700
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   ff15????????         |                     
            //   8b35????????         |                     

        $sequence_1 = { 8965f4 c745f8???????? 8b550c 33f6 8d4dd0 8975d8 8975d0 }
            // n = 7, score = 700
            //   8965f4               | mov                 dword ptr [ebp - 0xc], esp
            //   c745f8????????       |                     
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   33f6                 | xor                 esi, esi
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi

        $sequence_2 = { c780c000000016c1a419 c780c4000000086c371e c780c80000004c774827 c780cc000000b5bcb034 }
            // n = 4, score = 700
            //   c780c000000016c1a419     | mov    dword ptr [eax + 0xc0], 0x19a4c116
            //   c780c4000000086c371e     | mov    dword ptr [eax + 0xc4], 0x1e376c08
            //   c780c80000004c774827     | mov    dword ptr [eax + 0xc8], 0x2748774c
            //   c780cc000000b5bcb034     | mov    dword ptr [eax + 0xcc], 0x34b0bcb5

        $sequence_3 = { ffd6 57 ff15???????? 50 55 }
            // n = 5, score = 700
            //   ffd6                 | call                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   55                   | push                ebp

        $sequence_4 = { 52 8d8d30ffffff 50 8d9534ffffff 51 8d8538ffffff 52 }
            // n = 7, score = 700
            //   52                   | push                edx
            //   8d8d30ffffff         | lea                 ecx, [ebp - 0xd0]
            //   50                   | push                eax
            //   8d9534ffffff         | lea                 edx, [ebp - 0xcc]
            //   51                   | push                ecx
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]
            //   52                   | push                edx

        $sequence_5 = { c1e002 853c01 7428 8b5244 }
            // n = 4, score = 700
            //   c1e002               | shl                 eax, 2
            //   853c01               | test                dword ptr [ecx + eax], edi
            //   7428                 | je                  0x2a
            //   8b5244               | mov                 edx, dword ptr [edx + 0x44]

        $sequence_6 = { 8b35???????? 8bd0 8d4dec ffd6 8b45ec 50 }
            // n = 6, score = 700
            //   8b35????????         |                     
            //   8bd0                 | mov                 edx, eax
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   ffd6                 | call                esi
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax

        $sequence_7 = { ff522c 8b55d8 8b4dd0 8b45dc 8b9d5cfeffff 8955d0 }
            // n = 6, score = 700
            //   ff522c               | call                dword ptr [edx + 0x2c]
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   8b4dd0               | mov                 ecx, dword ptr [ebp - 0x30]
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8b9d5cfeffff         | mov                 ebx, dword ptr [ebp - 0x1a4]
            //   8955d0               | mov                 dword ptr [ebp - 0x30], edx

        $sequence_8 = { 8b55c8 51 52 56 ff502c 8b4590 8b8d5cfeffff }
            // n = 7, score = 700
            //   8b55c8               | mov                 edx, dword ptr [ebp - 0x38]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   56                   | push                esi
            //   ff502c               | call                dword ptr [eax + 0x2c]
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   8b8d5cfeffff         | mov                 ecx, dword ptr [ebp - 0x1a4]

        $sequence_9 = { 8b7c241c 33c0 51 89442414 89442410 8944240c }
            // n = 6, score = 700
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   33c0                 | xor                 eax, eax
            //   51                   | push                ecx
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax

    condition:
        7 of them and filesize < 1540096
}