rule win_bravonc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bravonc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bravonc"
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
        $sequence_0 = { 03c1 8b8ec0000000 034134 8b4df0 8d8401a1ebd96e 8945f0 e8???????? }
            // n = 7, score = 100
            //   03c1                 | add                 eax, ecx
            //   8b8ec0000000         | mov                 ecx, dword ptr [esi + 0xc0]
            //   034134               | add                 eax, dword ptr [ecx + 0x34]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8d8401a1ebd96e       | lea                 eax, [ecx + eax + 0x6ed9eba1]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   e8????????           |                     

        $sequence_1 = { 72a5 837e0813 7316 8b4608 8b4e0c 8b0485d8c34000 83248100 }
            // n = 7, score = 100
            //   72a5                 | jb                  0xffffffa7
            //   837e0813             | cmp                 dword ptr [esi + 8], 0x13
            //   7316                 | jae                 0x18
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   8b0485d8c34000       | mov                 eax, dword ptr [eax*4 + 0x40c3d8]
            //   83248100             | and                 dword ptr [ecx + eax*4], 0

        $sequence_2 = { 59 33c0 8dbd15ffffff f3ab }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8dbd15ffffff         | lea                 edi, [ebp - 0xeb]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_3 = { 03410c 8b4df0 8d84019979825a 8945f0 e8???????? 8945ec 8b86c0000000 }
            // n = 7, score = 100
            //   03410c               | add                 eax, dword ptr [ecx + 0xc]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8d84019979825a       | lea                 eax, [ecx + eax + 0x5a827999]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b86c0000000         | mov                 eax, dword ptr [esi + 0xc0]

        $sequence_4 = { 56 ff15???????? 6a01 8365f400 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   8365f400             | and                 dword ptr [ebp - 0xc], 0

        $sequence_5 = { 6a06 8d8d04ffffff 51 8bce ff7604 ff5024 85c0 }
            // n = 7, score = 100
            //   6a06                 | push                6
            //   8d8d04ffffff         | lea                 ecx, [ebp - 0xfc]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   ff7604               | push                dword ptr [esi + 4]
            //   ff5024               | call                dword ptr [eax + 0x24]
            //   85c0                 | test                eax, eax

        $sequence_6 = { e8???????? 8b7d10 6a04 5b 8d4de0 53 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   6a04                 | push                4
            //   5b                   | pop                 ebx
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   53                   | push                ebx

        $sequence_7 = { 75ea 6a2c 33c0 5e 40 8bd0 }
            // n = 6, score = 100
            //   75ea                 | jne                 0xffffffec
            //   6a2c                 | push                0x2c
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   40                   | inc                 eax
            //   8bd0                 | mov                 edx, eax

        $sequence_8 = { 8b4d14 8d843d05ffffff 8bd1 83c40c c1fa08 8810 }
            // n = 6, score = 100
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8d843d05ffffff       | lea                 eax, [ebp + edi - 0xfb]
            //   8bd1                 | mov                 edx, ecx
            //   83c40c               | add                 esp, 0xc
            //   c1fa08               | sar                 edx, 8
            //   8810                 | mov                 byte ptr [eax], dl

        $sequence_9 = { 8bd8 8b86c0000000 6a08 81e300ff00ff ff7038 e8???????? 25ff00ff00 }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   8b86c0000000         | mov                 eax, dword ptr [esi + 0xc0]
            //   6a08                 | push                8
            //   81e300ff00ff         | and                 ebx, 0xff00ff00
            //   ff7038               | push                dword ptr [eax + 0x38]
            //   e8????????           |                     
            //   25ff00ff00           | and                 eax, 0xff00ff

    condition:
        7 of them and filesize < 131072
}