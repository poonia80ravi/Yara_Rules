rule win_ayegent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ayegent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ayegent"
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
        $sequence_0 = { 50 ff15???????? 8b2d???????? 83f8ff a3???????? 0f84f1000000 6a02 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b2d????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   a3????????           |                     
            //   0f84f1000000         | je                  0xf7
            //   6a02                 | push                2

        $sequence_1 = { a3???????? c1f810 25ff7f0000 c3 55 8bec 6aff }
            // n = 7, score = 100
            //   a3????????           |                     
            //   c1f810               | sar                 eax, 0x10
            //   25ff7f0000           | and                 eax, 0x7fff
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   6aff                 | push                -1

        $sequence_2 = { 85c0 753e 389c2428020000 740c a1???????? }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   753e                 | jne                 0x40
            //   389c2428020000       | cmp                 byte ptr [esp + 0x228], bl
            //   740c                 | je                  0xe
            //   a1????????           |                     

        $sequence_3 = { 51 6804010000 aa e8???????? 83c408 ffd5 8d942444010000 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   6804010000           | push                0x104
            //   aa                   | stosb               byte ptr es:[edi], al
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   ffd5                 | call                ebp
            //   8d942444010000       | lea                 edx, [esp + 0x144]

        $sequence_4 = { eb26 8d4508 8db66c774000 6a00 50 }
            // n = 5, score = 100
            //   eb26                 | jmp                 0x28
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8db66c774000         | lea                 esi, [esi + 0x40776c]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_5 = { 3ad3 88542413 7ce0 8b0d???????? 8d542418 }
            // n = 5, score = 100
            //   3ad3                 | cmp                 dl, bl
            //   88542413             | mov                 byte ptr [esp + 0x13], dl
            //   7ce0                 | jl                  0xffffffe2
            //   8b0d????????         |                     
            //   8d542418             | lea                 edx, [esp + 0x18]

        $sequence_6 = { 8d0c8dc0764000 3bc1 7304 3910 7402 33c0 }
            // n = 6, score = 100
            //   8d0c8dc0764000       | lea                 ecx, [ecx*4 + 0x4076c0]
            //   3bc1                 | cmp                 eax, ecx
            //   7304                 | jae                 6
            //   3910                 | cmp                 dword ptr [eax], edx
            //   7402                 | je                  4
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 3bf3 7fc1 8b7c2414 8b0d???????? 8d542418 }
            // n = 5, score = 100
            //   3bf3                 | cmp                 esi, ebx
            //   7fc1                 | jg                  0xffffffc3
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   8b0d????????         |                     
            //   8d542418             | lea                 edx, [esp + 0x18]

        $sequence_8 = { ff15???????? 8d8c2450040000 68???????? 51 ffd5 b940000000 33c0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8d8c2450040000       | lea                 ecx, [esp + 0x450]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd5                 | call                ebp
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { f3ab 66ab aa 8d84244c030000 6804010000 50 53 }
            // n = 7, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d84244c030000       | lea                 eax, [esp + 0x34c]
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 90112
}