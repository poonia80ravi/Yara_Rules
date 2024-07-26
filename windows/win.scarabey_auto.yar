rule win_scarabey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.scarabey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scarabey"
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
        $sequence_0 = { 8bcb e8???????? 89851cffffff 3bd6 750c c78520ffffff60e95700 }
            // n = 6, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   89851cffffff         | mov                 dword ptr [ebp - 0xe4], eax
            //   3bd6                 | cmp                 edx, esi
            //   750c                 | jne                 0xe
            //   c78520ffffff60e95700     | mov    dword ptr [ebp - 0xe0], 0x57e960

        $sequence_1 = { 8975d4 c745cc20e75700 85c0 740b 8b0d???????? 894dcc eb15 }
            // n = 7, score = 100
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi
            //   c745cc20e75700       | mov                 dword ptr [ebp - 0x34], 0x57e720
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd
            //   8b0d????????         |                     
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   eb15                 | jmp                 0x17

        $sequence_2 = { 55 8bec 5d e9???????? e8???????? 8b80ec000000 c3 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   5d                   | pop                 ebp
            //   e9????????           |                     
            //   e8????????           |                     
            //   8b80ec000000         | mov                 eax, dword ptr [eax + 0xec]
            //   c3                   | ret                 

        $sequence_3 = { 7c03 4f 75a1 8b8584d6ffff 8b08 }
            // n = 5, score = 100
            //   7c03                 | jl                  5
            //   4f                   | dec                 edi
            //   75a1                 | jne                 0xffffffa3
            //   8b8584d6ffff         | mov                 eax, dword ptr [ebp - 0x297c]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_4 = { c74668d0af5700 6a0d e8???????? 59 8365fc00 ff7668 ff15???????? }
            // n = 7, score = 100
            //   c74668d0af5700       | mov                 dword ptr [esi + 0x68], 0x57afd0
            //   6a0d                 | push                0xd
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   ff7668               | push                dword ptr [esi + 0x68]
            //   ff15????????         |                     

        $sequence_5 = { c78558ffffff80185300 50 8d8d58ffffff 897dfc e8???????? 8d8d48ffffff e8???????? }
            // n = 7, score = 100
            //   c78558ffffff80185300     | mov    dword ptr [ebp - 0xa8], 0x531880
            //   50                   | push                eax
            //   8d8d58ffffff         | lea                 ecx, [ebp - 0xa8]
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   e8????????           |                     
            //   8d8d48ffffff         | lea                 ecx, [ebp - 0xb8]
            //   e8????????           |                     

        $sequence_6 = { 8d4c247c e8???????? 6a01 8d4c247c e8???????? 6a01 8d4c247c }
            // n = 7, score = 100
            //   8d4c247c             | lea                 ecx, [esp + 0x7c]
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d4c247c             | lea                 ecx, [esp + 0x7c]
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d4c247c             | lea                 ecx, [esp + 0x7c]

        $sequence_7 = { b867666666 f7ad00d7ffff 8b8514d7ffff c1fa02 8bca c1e91f 03ca }
            // n = 7, score = 100
            //   b867666666           | mov                 eax, 0x66666667
            //   f7ad00d7ffff         | imul                dword ptr [ebp - 0x2900]
            //   8b8514d7ffff         | mov                 eax, dword ptr [ebp - 0x28ec]
            //   c1fa02               | sar                 edx, 2
            //   8bca                 | mov                 ecx, edx
            //   c1e91f               | shr                 ecx, 0x1f
            //   03ca                 | add                 ecx, edx

        $sequence_8 = { ff15???????? 8bbdd8d6ffff 8d9564f0ffff 52 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8bbdd8d6ffff         | mov                 edi, dword ptr [ebp - 0x2928]
            //   8d9564f0ffff         | lea                 edx, [ebp - 0xf9c]
            //   52                   | push                edx

        $sequence_9 = { 51 6a01 6880000000 52 ffd7 8b8694000000 8b4e20 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   6a01                 | push                1
            //   6880000000           | push                0x80
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   8b8694000000         | mov                 eax, dword ptr [esi + 0x94]
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]

    condition:
        7 of them and filesize < 3580928
}