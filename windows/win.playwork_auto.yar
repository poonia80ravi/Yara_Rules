rule win_playwork_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.playwork."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.playwork"
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
        $sequence_0 = { ff750c ffd6 ff4508 83c720 8b4508 }
            // n = 5, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ffd6                 | call                esi
            //   ff4508               | inc                 dword ptr [ebp + 8]
            //   83c720               | add                 edi, 0x20
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_1 = { 56 56 68???????? 56 56 ffd7 5f }
            // n = 7, score = 100
            //   56                   | push                esi
            //   56                   | push                esi
            //   68????????           |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   5f                   | pop                 edi

        $sequence_2 = { 55 8bec 81ec68060000 56 8b35???????? 57 }
            // n = 6, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec68060000         | sub                 esp, 0x668
            //   56                   | push                esi
            //   8b35????????         |                     
            //   57                   | push                edi

        $sequence_3 = { 3bc6 894304 7421 56 }
            // n = 4, score = 100
            //   3bc6                 | cmp                 eax, esi
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   7421                 | je                  0x23
            //   56                   | push                esi

        $sequence_4 = { 56 57 8d4590 6aff 50 53 53 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d4590               | lea                 eax, [ebp - 0x70]
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_5 = { e8???????? 83c40c 8d4de4 ff75f0 57 e8???????? 8d4de4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   57                   | push                edi
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_6 = { 56 89442434 e8???????? 56 89442448 e8???????? 8944243c }
            // n = 7, score = 100
            //   56                   | push                esi
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   e8????????           |                     
            //   56                   | push                esi
            //   89442448             | mov                 dword ptr [esp + 0x48], eax
            //   e8????????           |                     
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax

        $sequence_7 = { 56 57 8d85f8fdffff 6804010000 50 ff15???????? }
            // n = 6, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { ff75f0 57 e8???????? 8d4de4 e8???????? 8d856cfcffff 50 }
            // n = 7, score = 100
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   57                   | push                edi
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   8d856cfcffff         | lea                 eax, [ebp - 0x394]
            //   50                   | push                eax

        $sequence_9 = { 8b500c 83e904 895610 0f8469010000 49 49 0f84df000000 }
            // n = 7, score = 100
            //   8b500c               | mov                 edx, dword ptr [eax + 0xc]
            //   83e904               | sub                 ecx, 4
            //   895610               | mov                 dword ptr [esi + 0x10], edx
            //   0f8469010000         | je                  0x16f
            //   49                   | dec                 ecx
            //   49                   | dec                 ecx
            //   0f84df000000         | je                  0xe5

    condition:
        7 of them and filesize < 360448
}