rule win_deltas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.deltas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltas"
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
        $sequence_0 = { 897c241c e8???????? 85c0 0f850e020000 682c010000 ffd3 8b4528 }
            // n = 7, score = 200
            //   897c241c             | mov                 dword ptr [esp + 0x1c], edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f850e020000         | jne                 0x214
            //   682c010000           | push                0x12c
            //   ffd3                 | call                ebx
            //   8b4528               | mov                 eax, dword ptr [ebp + 0x28]

        $sequence_1 = { 8d7c242c 8d74243c 33d2 f3a7 7574 8b4510 }
            // n = 6, score = 200
            //   8d7c242c             | lea                 edi, [esp + 0x2c]
            //   8d74243c             | lea                 esi, [esp + 0x3c]
            //   33d2                 | xor                 edx, edx
            //   f3a7                 | repe cmpsd          dword ptr [esi], dword ptr es:[edi]
            //   7574                 | jne                 0x76
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_2 = { 7319 833800 7508 8b3a 46 8938 83c204 }
            // n = 7, score = 200
            //   7319                 | jae                 0x1b
            //   833800               | cmp                 dword ptr [eax], 0
            //   7508                 | jne                 0xa
            //   8b3a                 | mov                 edi, dword ptr [edx]
            //   46                   | inc                 esi
            //   8938                 | mov                 dword ptr [eax], edi
            //   83c204               | add                 edx, 4

        $sequence_3 = { a3???????? ffd6 a3???????? 5f 33c0 5e 83c420 }
            // n = 7, score = 200
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   83c420               | add                 esp, 0x20

        $sequence_4 = { 81ec0c030000 56 57 b940000000 33c0 8d7c2409 }
            // n = 6, score = 200
            //   81ec0c030000         | sub                 esp, 0x30c
            //   56                   | push                esi
            //   57                   | push                edi
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8d7c2409             | lea                 edi, [esp + 9]

        $sequence_5 = { 57 33f6 b922000000 33c0 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   b922000000           | mov                 ecx, 0x22
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 56 83c508 8d7af8 57 6a01 55 ffd3 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   83c508               | add                 ebp, 8
            //   8d7af8               | lea                 edi, [edx - 8]
            //   57                   | push                edi
            //   6a01                 | push                1
            //   55                   | push                ebp
            //   ffd3                 | call                ebx

        $sequence_7 = { 03c5 8b6c2448 8d8408aac7b6e9 8bc8 c1e114 }
            // n = 5, score = 200
            //   03c5                 | add                 eax, ebp
            //   8b6c2448             | mov                 ebp, dword ptr [esp + 0x48]
            //   8d8408aac7b6e9       | lea                 eax, [eax + ecx - 0x16493856]
            //   8bc8                 | mov                 ecx, eax
            //   c1e114               | shl                 ecx, 0x14

        $sequence_8 = { 8b442434 03d8 8bc7 8d9c1362251ef6 8bd3 c1ea1b c1e305 }
            // n = 7, score = 200
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   03d8                 | add                 ebx, eax
            //   8bc7                 | mov                 eax, edi
            //   8d9c1362251ef6       | lea                 ebx, [ebx + edx - 0x9e1da9e]
            //   8bd3                 | mov                 edx, ebx
            //   c1ea1b               | shr                 edx, 0x1b
            //   c1e305               | shl                 ebx, 5

        $sequence_9 = { 7519 8b8c24a0000000 5f 5e 5d 8919 5b }
            // n = 7, score = 200
            //   7519                 | jne                 0x1b
            //   8b8c24a0000000       | mov                 ecx, dword ptr [esp + 0xa0]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   8919                 | mov                 dword ptr [ecx], ebx
            //   5b                   | pop                 ebx

    condition:
        7 of them and filesize < 90112
}