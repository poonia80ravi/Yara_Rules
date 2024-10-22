rule win_younglotus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.younglotus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.younglotus"
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
        $sequence_0 = { 6802000080 e8???????? 83c41c 6a01 }
            // n = 4, score = 1000
            //   6802000080           | push                0x80000002
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   6a01                 | push                1

        $sequence_1 = { 8b4210 50 ff15???????? 8b4dfc 89819c000000 68???????? }
            // n = 6, score = 800
            //   8b4210               | mov                 eax, dword ptr [edx + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   89819c000000         | mov                 dword ptr [ecx + 0x9c], eax
            //   68????????           |                     

        $sequence_2 = { ff15???????? 8945f4 8b55ec 837a0400 0f8674010000 8b45ec 8b4df0 }
            // n = 7, score = 800
            //   ff15????????         |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   837a0400             | cmp                 dword ptr [edx + 4], 0
            //   0f8674010000         | jbe                 0x17a
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_3 = { 8b08 81e100000080 85c9 741c }
            // n = 4, score = 800
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   81e100000080         | and                 ecx, 0x80000000
            //   85c9                 | test                ecx, ecx
            //   741c                 | je                  0x1e

        $sequence_4 = { 33c0 eb14 8b4df8 8b55e8 03511c 8b45fc }
            // n = 6, score = 800
            //   33c0                 | xor                 eax, eax
            //   eb14                 | jmp                 0x16
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   03511c               | add                 edx, dword ptr [ecx + 0x1c]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_5 = { ff15???????? 8b55fc 8982f4000000 68???????? 8b45fc 8b4814 }
            // n = 6, score = 800
            //   ff15????????         |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8982f4000000         | mov                 dword ptr [edx + 0xf4], eax
            //   68????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4814               | mov                 ecx, dword ptr [eax + 0x14]

        $sequence_6 = { 8b4dfc 894108 8b4dfc e8???????? 50 8b4dfc }
            // n = 6, score = 800
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_7 = { 7407 33c0 e9???????? 6a04 6800200000 8b45f0 }
            // n = 6, score = 800
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   6a04                 | push                4
            //   6800200000           | push                0x2000
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_8 = { 53 56 57 68???????? ff15???????? 8945dc 68???????? }
            // n = 7, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   ff15????????         |                     
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   68????????           |                     

        $sequence_9 = { bf00200000 8b1d???????? 6a04 57 }
            // n = 4, score = 400
            //   bf00200000           | mov                 edi, 0x2000
            //   8b1d????????         |                     
            //   6a04                 | push                4
            //   57                   | push                edi

        $sequence_10 = { ffd6 eb0a ff7508 50 ff15???????? 6a10 }
            // n = 6, score = 400
            //   ffd6                 | call                esi
            //   eb0a                 | jmp                 0xc
            //   ff7508               | push                dword ptr [ebp + 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a10                 | push                0x10

        $sequence_11 = { ff75fc ffd3 8b5d08 8945f8 }
            // n = 4, score = 400
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ffd3                 | call                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_12 = { 03c1 8b4dfc 57 56 }
            // n = 4, score = 400
            //   03c1                 | add                 eax, ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_13 = { 8b45fc 33c9 6a04 6800100000 894704 894f0c 894f08 }
            // n = 7, score = 400
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   33c9                 | xor                 ecx, ecx
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   894f0c               | mov                 dword ptr [edi + 0xc], ecx
            //   894f08               | mov                 dword ptr [edi + 8], ecx

        $sequence_14 = { 8945f4 7e49 6a04 53 50 8b46fc }
            // n = 6, score = 400
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   7e49                 | jle                 0x4b
            //   6a04                 | push                4
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8b46fc               | mov                 eax, dword ptr [esi - 4]

        $sequence_15 = { c706???????? 740f ff74240c 68???????? ff15???????? 8b442410 }
            // n = 6, score = 400
            //   c706????????         |                     
            //   740f                 | je                  0x11
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]

    condition:
        7 of them and filesize < 106496
}