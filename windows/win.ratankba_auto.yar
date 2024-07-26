rule win_ratankba_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ratankba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratankba"
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
        $sequence_0 = { 399eb8000000 720f 8b8ea4000000 51 e8???????? }
            // n = 5, score = 400
            //   399eb8000000         | cmp                 dword ptr [esi + 0xb8], ebx
            //   720f                 | jb                  0x11
            //   8b8ea4000000         | mov                 ecx, dword ptr [esi + 0xa4]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_1 = { e8???????? 83c404 8b8394000000 33f6 c78538efffff00280000 }
            // n = 5, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b8394000000         | mov                 eax, dword ptr [ebx + 0x94]
            //   33f6                 | xor                 esi, esi
            //   c78538efffff00280000     | mov    dword ptr [ebp - 0x10c8], 0x2800

        $sequence_2 = { 8b5508 83c404 52 57 c70700000000 e8???????? 84c0 }
            // n = 7, score = 400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83c404               | add                 esp, 4
            //   52                   | push                edx
            //   57                   | push                edi
            //   c70700000000         | mov                 dword ptr [edi], 0
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_3 = { 8b04c1 52 50 53 e8???????? 83c40c }
            // n = 6, score = 400
            //   8b04c1               | mov                 eax, dword ptr [ecx + eax*8]
            //   52                   | push                edx
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_4 = { e8???????? 83c404 33d2 89beb8000000 c786b400000000000000 668996a4000000 399e8c000000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33d2                 | xor                 edx, edx
            //   89beb8000000         | mov                 dword ptr [esi + 0xb8], edi
            //   c786b400000000000000     | mov    dword ptr [esi + 0xb4], 0
            //   668996a4000000       | mov                 word ptr [esi + 0xa4], dx
            //   399e8c000000         | cmp                 dword ptr [esi + 0x8c], ebx

        $sequence_5 = { 8bc6 8bcb e8???????? 8b17 5f 5e }
            // n = 6, score = 400
            //   8bc6                 | mov                 eax, esi
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_6 = { 0f84270a0000 8b8d00efffff 3bcf 0f84ee000000 33c0 8985bceeffff 8985c0eeffff }
            // n = 7, score = 400
            //   0f84270a0000         | je                  0xa2d
            //   8b8d00efffff         | mov                 ecx, dword ptr [ebp - 0x1100]
            //   3bcf                 | cmp                 ecx, edi
            //   0f84ee000000         | je                  0xf4
            //   33c0                 | xor                 eax, eax
            //   8985bceeffff         | mov                 dword ptr [ebp - 0x1144], eax
            //   8985c0eeffff         | mov                 dword ptr [ebp - 0x1140], eax

        $sequence_7 = { 833b00 75a0 53 8d45e4 50 e8???????? }
            // n = 6, score = 400
            //   833b00               | cmp                 dword ptr [ebx], 0
            //   75a0                 | jne                 0xffffffa2
            //   53                   | push                ebx
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 8b06 0fb708 83f95d 0f84c5000000 }
            // n = 4, score = 400
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   0fb708               | movzx               ecx, word ptr [eax]
            //   83f95d               | cmp                 ecx, 0x5d
            //   0f84c5000000         | je                  0xcb

        $sequence_9 = { 74b4 8bd7 e8???????? 8bf0 e9???????? 66833b00 }
            // n = 6, score = 400
            //   74b4                 | je                  0xffffffb6
            //   8bd7                 | mov                 edx, edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   e9????????           |                     
            //   66833b00             | cmp                 word ptr [ebx], 0

    condition:
        7 of them and filesize < 303104
}