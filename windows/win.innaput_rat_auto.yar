rule win_innaput_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.innaput_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.innaput_rat"
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
        $sequence_0 = { ff5708 56 ff5708 59 59 3b5d08 }
            // n = 6, score = 500
            //   ff5708               | call                dword ptr [edi + 8]
            //   56                   | push                esi
            //   ff5708               | call                dword ptr [edi + 8]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3b5d08               | cmp                 ebx, dword ptr [ebp + 8]

        $sequence_1 = { 8b460c 83f8ff 7404 3bc3 }
            // n = 4, score = 500
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   83f8ff               | cmp                 eax, -1
            //   7404                 | je                  6
            //   3bc3                 | cmp                 eax, ebx

        $sequence_2 = { 740e 68???????? 8d858cf9ffff 50 }
            // n = 4, score = 500
            //   740e                 | je                  0x10
            //   68????????           |                     
            //   8d858cf9ffff         | lea                 eax, [ebp - 0x674]
            //   50                   | push                eax

        $sequence_3 = { 75fa 6a0c ff5704 59 8906 3bc3 }
            // n = 6, score = 500
            //   75fa                 | jne                 0xfffffffc
            //   6a0c                 | push                0xc
            //   ff5704               | call                dword ptr [edi + 4]
            //   59                   | pop                 ecx
            //   8906                 | mov                 dword ptr [esi], eax
            //   3bc3                 | cmp                 eax, ebx

        $sequence_4 = { 57 6800000100 e8???????? 6a02 }
            // n = 4, score = 500
            //   57                   | push                edi
            //   6800000100           | push                0x10000
            //   e8????????           |                     
            //   6a02                 | push                2

        $sequence_5 = { 7413 3bc6 740f 8b4d08 e8???????? 3b450c }
            // n = 6, score = 500
            //   7413                 | je                  0x15
            //   3bc6                 | cmp                 eax, esi
            //   740f                 | je                  0x11
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 7412 53 ff7604 ff15???????? 85c0 }
            // n = 5, score = 500
            //   7412                 | je                  0x14
            //   53                   | push                ebx
            //   ff7604               | push                dword ptr [esi + 4]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { ff750c 8d8608020000 50 ffd7 8b4510 898618060000 }
            // n = 6, score = 500
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d8608020000         | lea                 eax, [esi + 0x208]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   898618060000         | mov                 dword ptr [esi + 0x618], eax

        $sequence_8 = { 3910 7418 8b00 eb02 8b01 }
            // n = 5, score = 500
            //   3910                 | cmp                 dword ptr [eax], edx
            //   7418                 | je                  0x1a
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   eb02                 | jmp                 4
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_9 = { 85c0 750c ffb71c060000 ff15???????? 57 e8???????? }
            // n = 6, score = 500
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe
            //   ffb71c060000         | push                dword ptr [edi + 0x61c]
            //   ff15????????         |                     
            //   57                   | push                edi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 73728
}