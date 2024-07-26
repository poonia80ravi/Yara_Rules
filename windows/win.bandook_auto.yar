rule win_bandook_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bandook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bandook"
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
        $sequence_0 = { 8d442424 0f57c0 50 57 0f2944242c ff15???????? }
            // n = 6, score = 100
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   0f57c0               | xorps               xmm0, xmm0
            //   50                   | push                eax
            //   57                   | push                edi
            //   0f2944242c           | movaps              xmmword ptr [esp + 0x2c], xmm0
            //   ff15????????         |                     

        $sequence_1 = { 0f8479ffffff 68???????? 8d4d28 e8???????? 8d4528 c745fc05000000 50 }
            // n = 7, score = 100
            //   0f8479ffffff         | je                  0xffffff7f
            //   68????????           |                     
            //   8d4d28               | lea                 ecx, [ebp + 0x28]
            //   e8????????           |                     
            //   8d4528               | lea                 eax, [ebp + 0x28]
            //   c745fc05000000       | mov                 dword ptr [ebp - 4], 5
            //   50                   | push                eax

        $sequence_2 = { ff15???????? 53 ff15???????? ff75dc 6a00 ff15???????? 56 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_3 = { 85c0 746e 8d842450010000 50 8d842460010000 68???????? 50 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   746e                 | je                  0x70
            //   8d842450010000       | lea                 eax, [esp + 0x150]
            //   50                   | push                eax
            //   8d842460010000       | lea                 eax, [esp + 0x160]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_4 = { 8b4e18 85c9 743e 837e1400 7438 8b7e20 33db }
            // n = 7, score = 100
            //   8b4e18               | mov                 ecx, dword ptr [esi + 0x18]
            //   85c9                 | test                ecx, ecx
            //   743e                 | je                  0x40
            //   837e1400             | cmp                 dword ptr [esi + 0x14], 0
            //   7438                 | je                  0x3a
            //   8b7e20               | mov                 edi, dword ptr [esi + 0x20]
            //   33db                 | xor                 ebx, ebx

        $sequence_5 = { 0f8464100000 e9???????? 55 8bec a1???????? 83e01f 6a20 }
            // n = 7, score = 100
            //   0f8464100000         | je                  0x106a
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   83e01f               | and                 eax, 0x1f
            //   6a20                 | push                0x20

        $sequence_6 = { b9???????? 0f1f440000 8a01 3a02 751a 84c0 }
            // n = 6, score = 100
            //   b9????????           |                     
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   3a02                 | cmp                 al, byte ptr [edx]
            //   751a                 | jne                 0x1c
            //   84c0                 | test                al, al

        $sequence_7 = { 83c40c 8d44240c 6a00 50 6800080000 8d8424fc020000 50 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   6800080000           | push                0x800
            //   8d8424fc020000       | lea                 eax, [esp + 0x2fc]
            //   50                   | push                eax

        $sequence_8 = { c685c0fdffff00 e8???????? c645fc02 8d8dd8fdffff 6a07 68???????? c785e8fdffff00000000 }
            // n = 7, score = 100
            //   c685c0fdffff00       | mov                 byte ptr [ebp - 0x240], 0
            //   e8????????           |                     
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8d8dd8fdffff         | lea                 ecx, [ebp - 0x228]
            //   6a07                 | push                7
            //   68????????           |                     
            //   c785e8fdffff00000000     | mov    dword ptr [ebp - 0x218], 0

        $sequence_9 = { 89414c 3bf7 0f85e8feffff 8b75ac 33c0 0f1045d4 8b55d0 }
            // n = 7, score = 100
            //   89414c               | mov                 dword ptr [ecx + 0x4c], eax
            //   3bf7                 | cmp                 esi, edi
            //   0f85e8feffff         | jne                 0xfffffeee
            //   8b75ac               | mov                 esi, dword ptr [ebp - 0x54]
            //   33c0                 | xor                 eax, eax
            //   0f1045d4             | movups              xmm0, xmmword ptr [ebp - 0x2c]
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]

    condition:
        7 of them and filesize < 23088128
}