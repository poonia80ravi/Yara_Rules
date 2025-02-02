rule win_casper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.casper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.casper"
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
        $sequence_0 = { e8???????? 59 3bf8 72e3 6a22 8bc3 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   3bf8                 | cmp                 edi, eax
            //   72e3                 | jb                  0xffffffe5
            //   6a22                 | push                0x22
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_1 = { ff5004 3945b8 0f85e7020000 57 ff75fc ff5364 8945f8 }
            // n = 7, score = 100
            //   ff5004               | call                dword ptr [eax + 4]
            //   3945b8               | cmp                 dword ptr [ebp - 0x48], eax
            //   0f85e7020000         | jne                 0x2ed
            //   57                   | push                edi
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff5364               | call                dword ptr [ebx + 0x64]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_2 = { 50 51 57 e8???????? 85c0 7407 57 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   57                   | push                edi

        $sequence_3 = { 56 57 68???????? 8bf1 e8???????? 8b4604 59 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   59                   | pop                 ecx

        $sequence_4 = { 0f841c020000 397de0 0f846ffeffff 8b450c 3bc7 7414 b9cc000000 }
            // n = 7, score = 100
            //   0f841c020000         | je                  0x222
            //   397de0               | cmp                 dword ptr [ebp - 0x20], edi
            //   0f846ffeffff         | je                  0xfffffe75
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   3bc7                 | cmp                 eax, edi
            //   7414                 | je                  0x16
            //   b9cc000000           | mov                 ecx, 0xcc

        $sequence_5 = { 751a 48 8906 8b13 c6041000 33c0 }
            // n = 6, score = 100
            //   751a                 | jne                 0x1c
            //   48                   | dec                 eax
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   c6041000             | mov                 byte ptr [eax + edx], 0
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { ff75fc 897d0c c7450800080000 e8???????? 85c0 7569 }
            // n = 6, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   897d0c               | mov                 dword ptr [ebp + 0xc], edi
            //   c7450800080000       | mov                 dword ptr [ebp + 8], 0x800
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7569                 | jne                 0x6b

        $sequence_7 = { ff7508 e8???????? 8b1f 035dfc 8945f4 8b4710 0345fc }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8b1f                 | mov                 ebx, dword ptr [edi]
            //   035dfc               | add                 ebx, dword ptr [ebp - 4]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]

        $sequence_8 = { 83e4f8 83ec1c 8364241400 53 56 57 8bd9 }
            // n = 7, score = 100
            //   83e4f8               | and                 esp, 0xfffffff8
            //   83ec1c               | sub                 esp, 0x1c
            //   8364241400           | and                 dword ptr [esp + 0x14], 0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bd9                 | mov                 ebx, ecx

        $sequence_9 = { eb02 33c0 68???????? 8bf0 8903 e8???????? 5f }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   68????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8903                 | mov                 dword ptr [ebx], eax
            //   e8????????           |                     
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 434176
}