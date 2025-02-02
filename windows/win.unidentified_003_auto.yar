rule win_unidentified_003_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_003."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_003"
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
        $sequence_0 = { 83c0fc 50 8d4704 50 686467bceb }
            // n = 5, score = 100
            //   83c0fc               | add                 eax, -4
            //   50                   | push                eax
            //   8d4704               | lea                 eax, [edi + 4]
            //   50                   | push                eax
            //   686467bceb           | push                0xebbc6764

        $sequence_1 = { 56 8bf0 7468 57 ff15???????? 85c0 755d }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   7468                 | je                  0x6a
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   755d                 | jne                 0x5f

        $sequence_2 = { 8bc6 5e c21000 b805400080 c21400 }
            // n = 5, score = 100
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c21000               | ret                 0x10
            //   b805400080           | mov                 eax, 0x80004005
            //   c21400               | ret                 0x14

        $sequence_3 = { 53 6afc 50 ff522c 85c0 0f88e1000000 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   6afc                 | push                -4
            //   50                   | push                eax
            //   ff522c               | call                dword ptr [edx + 0x2c]
            //   85c0                 | test                eax, eax
            //   0f88e1000000         | js                  0xe7

        $sequence_4 = { f3a4 e8???????? 59 59 85c0 7514 8b7c2410 }
            // n = 7, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7514                 | jne                 0x16
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]

        $sequence_5 = { 8b10 8b4d14 8b7d10 8bf2 33db f3a6 7414 }
            // n = 7, score = 100
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   8bf2                 | mov                 esi, edx
            //   33db                 | xor                 ebx, ebx
            //   f3a6                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   7414                 | je                  0x16

        $sequence_6 = { 75e5 2b45e8 8b750c eb02 33c0 }
            // n = 5, score = 100
            //   75e5                 | jne                 0xffffffe7
            //   2b45e8               | sub                 eax, dword ptr [ebp - 0x18]
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 50 51 56 8d85c8fbffff }
            // n = 4, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   56                   | push                esi
            //   8d85c8fbffff         | lea                 eax, [ebp - 0x438]

        $sequence_8 = { 8975c8 c78550ffffff44000000 e8???????? 33c0 8975b8 }
            // n = 5, score = 100
            //   8975c8               | mov                 dword ptr [ebp - 0x38], esi
            //   c78550ffffff44000000     | mov    dword ptr [ebp - 0xb0], 0x44
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   8975b8               | mov                 dword ptr [ebp - 0x48], esi

        $sequence_9 = { 3bc3 0f84df000000 8b08 53 53 8d55cc 52 }
            // n = 7, score = 100
            //   3bc3                 | cmp                 eax, ebx
            //   0f84df000000         | je                  0xe5
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d55cc               | lea                 edx, [ebp - 0x34]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 57344
}