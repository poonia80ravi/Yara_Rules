rule win_termite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.termite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.termite"
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
        $sequence_0 = { e9???????? a1???????? 8b4d10 85c0 8b11 7454 }
            // n = 6, score = 200
            //   e9????????           |                     
            //   a1????????           |                     
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   85c0                 | test                eax, eax
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   7454                 | je                  0x56

        $sequence_1 = { 893424 e8???????? 8b07 c7442404???????? 893424 8944240c 8d45e1 }
            // n = 7, score = 200
            //   893424               | mov                 dword ptr [esp], esi
            //   e8????????           |                     
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   c7442404????????     |                     
            //   893424               | mov                 dword ptr [esp], esi
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   8d45e1               | lea                 eax, [ebp - 0x1f]

        $sequence_2 = { 890424 e8???????? 8945f4 837df400 7507 b8ffffffff eb7e }
            // n = 7, score = 200
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7507                 | jne                 9
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   eb7e                 | jmp                 0x80

        $sequence_3 = { e8???????? 83f8ff 7507 b800000000 eb48 e8???????? }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7507                 | jne                 9
            //   b800000000           | mov                 eax, 0
            //   eb48                 | jmp                 0x4a
            //   e8????????           |                     

        $sequence_4 = { e8???????? c70424???????? e8???????? c704240a000000 e8???????? 8b45f4 c9 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c70424????????       |                     
            //   e8????????           |                     
            //   c704240a000000       | mov                 dword ptr [esp], 0xa
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   c9                   | leave               

        $sequence_5 = { 83c20c 89542404 890424 e8???????? 8b450c 8b4010 c744240804000000 }
            // n = 7, score = 200
            //   83c20c               | add                 edx, 0xc
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   c744240804000000     | mov                 dword ptr [esp + 8], 4

        $sequence_6 = { 890424 e8???????? 8b450c 8b400c c744240804000000 8d9568feffff }
            // n = 6, score = 200
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   c744240804000000     | mov                 dword ptr [esp + 8], 4
            //   8d9568feffff         | lea                 edx, [ebp - 0x198]

        $sequence_7 = { 39ca 7d22 8b5d10 8b7c8bfc }
            // n = 4, score = 200
            //   39ca                 | cmp                 edx, ecx
            //   7d22                 | jge                 0x24
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b7c8bfc             | mov                 edi, dword ptr [ebx + ecx*4 - 4]

        $sequence_8 = { 740e eb28 83f803 7415 83f804 7409 eb1c }
            // n = 7, score = 200
            //   740e                 | je                  0x10
            //   eb28                 | jmp                 0x2a
            //   83f803               | cmp                 eax, 3
            //   7415                 | je                  0x17
            //   83f804               | cmp                 eax, 4
            //   7409                 | je                  0xb
            //   eb1c                 | jmp                 0x1e

        $sequence_9 = { b8ffffffff eb32 eb2b c70424???????? e8???????? c70424???????? e8???????? }
            // n = 7, score = 200
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   eb32                 | jmp                 0x34
            //   eb2b                 | jmp                 0x2d
            //   c70424????????       |                     
            //   e8????????           |                     
            //   c70424????????       |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 312320
}