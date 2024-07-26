rule win_kagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.kagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kagent"
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
        $sequence_0 = { e8???????? 83c404 c7450c00000000 8b4518 85c0 7409 50 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c7450c00000000       | mov                 dword ptr [ebp + 0xc], 0
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   50                   | push                eax

        $sequence_1 = { 0bc8 51 e8???????? 33c9 8945ec c645f001 895de8 }
            // n = 7, score = 400
            //   0bc8                 | or                  ecx, eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   c645f001             | mov                 byte ptr [ebp - 0x10], 1
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx

        $sequence_2 = { 8b45e8 3bc6 0f8355010000 57 56 }
            // n = 5, score = 400
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   3bc6                 | cmp                 eax, esi
            //   0f8355010000         | jae                 0x15b
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_3 = { 50 50 52 e8???????? 8b45ec 50 e8???????? }
            // n = 7, score = 400
            //   50                   | push                eax
            //   50                   | push                eax
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { b801000000 ba02000000 f7e2 0f90c1 c645fc03 885e68 f7d9 }
            // n = 7, score = 400
            //   b801000000           | mov                 eax, 1
            //   ba02000000           | mov                 edx, 2
            //   f7e2                 | mul                 edx
            //   0f90c1               | seto                cl
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   885e68               | mov                 byte ptr [esi + 0x68], bl
            //   f7d9                 | neg                 ecx

        $sequence_5 = { 0fbe9c05fcfeffff 8a441701 42 3c3d 7504 33ff eb0b }
            // n = 7, score = 400
            //   0fbe9c05fcfeffff     | movsx               ebx, byte ptr [ebp + eax - 0x104]
            //   8a441701             | mov                 al, byte ptr [edi + edx + 1]
            //   42                   | inc                 edx
            //   3c3d                 | cmp                 al, 0x3d
            //   7504                 | jne                 6
            //   33ff                 | xor                 edi, edi
            //   eb0b                 | jmp                 0xd

        $sequence_6 = { 83c404 8b8544ffffff 3bc6 7409 50 e8???????? }
            // n = 6, score = 400
            //   83c404               | add                 esp, 4
            //   8b8544ffffff         | mov                 eax, dword ptr [ebp - 0xbc]
            //   3bc6                 | cmp                 eax, esi
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { e8???????? 894624 c6462801 8b4624 33c9 895e20 668908 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   894624               | mov                 dword ptr [esi + 0x24], eax
            //   c6462801             | mov                 byte ptr [esi + 0x28], 1
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   33c9                 | xor                 ecx, ecx
            //   895e20               | mov                 dword ptr [esi + 0x20], ebx
            //   668908               | mov                 word ptr [eax], cx

        $sequence_8 = { 7cd7 5f 5e b802000000 5b c3 }
            // n = 6, score = 400
            //   7cd7                 | jl                  0xffffffd9
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   b802000000           | mov                 eax, 2
            //   5b                   | pop                 ebx
            //   c3                   | ret                 

        $sequence_9 = { 51 e8???????? 33c9 8945e0 885de4 c745dc00000000 }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   885de4               | mov                 byte ptr [ebp - 0x1c], bl
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0

    condition:
        7 of them and filesize < 4972544
}