rule win_juicy_potato_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.juicy_potato."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.juicy_potato"
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
        $sequence_0 = { 48894108 48894110 488d058f7f0200 488901 488bc1 c3 4053 }
            // n = 7, score = 100
            //   48894108             | arpl                cx, cx
            //   48894110             | dec                 eax
            //   488d058f7f0200       | lea                 edx, [0x3d1d4]
            //   488901               | dec                 eax
            //   488bc1               | mov                 eax, ecx
            //   c3                   | js                  0xc0
            //   4053                 | jae                 0xba

        $sequence_1 = { c744246801000000 488905???????? 8905???????? 448d400c 488b15???????? 488d0da0040500 }
            // n = 6, score = 100
            //   c744246801000000     | mov                 dword ptr [ecx], eax
            //   488905????????       |                     
            //   8905????????         |                     
            //   448d400c             | dec                 eax
            //   488b15????????       |                     
            //   488d0da0040500       | mov                 edi, ecx

        $sequence_2 = { 488d1593390300 488d4c2420 e8???????? cc 488d4c2420 e8???????? 488d15a7350300 }
            // n = 7, score = 100
            //   488d1593390300       | lea                 eax, [0xfffe785c]
            //   488d4c2420           | dec                 eax
            //   e8????????           |                     
            //   cc                   | mov                 dword ptr [esp + 0x30], eax
            //   488d4c2420           | jmp                 0x38d
            //   e8????????           |                     
            //   488d15a7350300       | dec                 eax

        $sequence_3 = { 488d0527200400 eb04 4883c024 4883c428 c3 4883ec28 }
            // n = 6, score = 100
            //   488d0527200400       | nop                 
            //   eb04                 | inc                 ecx
            //   4883c024             | mov                 ecx, 0x10
            //   4883c428             | dec                 esp
            //   c3                   | lea                 eax, [ebp + 8]
            //   4883ec28             | xor                 edx, edx

        $sequence_4 = { 81ca00000780 85c0 0f4ed0 e8???????? 488d1546380200 488d4c2420 e8???????? }
            // n = 7, score = 100
            //   81ca00000780         | mov                 esp, ecx
            //   85c0                 | dec                 ecx
            //   0f4ed0               | mov                 ebp, eax
            //   e8????????           |                     
            //   488d1546380200       | dec                 esp
            //   488d4c2420           | mov                 ebp, edx
            //   e8????????           |                     

        $sequence_5 = { 488d4c2420 e8???????? 488d15dbe90200 488d4c2420 e8???????? cc }
            // n = 6, score = 100
            //   488d4c2420           | test                dl, 1
            //   e8????????           |                     
            //   488d15dbe90200       | je                  0x1095
            //   488d4c2420           | dec                 eax
            //   e8????????           |                     
            //   cc                   | sub                 esp, 0x20

        $sequence_6 = { 754c 48ffc1 4883f907 7546 4183c0fa 4183f8ff }
            // n = 6, score = 100
            //   754c                 | mov                 ebx, eax
            //   48ffc1               | inc                 esp
            //   4883f907             | mov                 eax, dword ptr [edi]
            //   7546                 | dec                 eax
            //   4183c0fa             | mov                 edx, eax
            //   4183f8ff             | dec                 eax

        $sequence_7 = { 4983c8ff 660f1f440000 49ffc0 6642390442 75f6 488d0dbffe0400 }
            // n = 6, score = 100
            //   4983c8ff             | dec                 eax
            //   660f1f440000         | mov                 dword ptr [ecx + 0x10], eax
            //   49ffc0               | dec                 eax
            //   6642390442           | lea                 eax, [0xdf53]
            //   75f6                 | dec                 eax
            //   488d0dbffe0400       | mov                 dword ptr [ecx], eax

        $sequence_8 = { 753b 8705???????? eb33 8364242800 488d05161d0000 4889442430 eb14 }
            // n = 7, score = 100
            //   753b                 | add                 esp, 0x20
            //   8705????????         |                     
            //   eb33                 | pop                 edi
            //   8364242800           | ret                 
            //   488d05161d0000       | inc                 eax
            //   4889442430           | push                ebx
            //   eb14                 | dec                 eax

        $sequence_9 = { 4c8d0de9db0200 b905000000 4c8d05d5db0200 488d155ec30200 e8???????? 488bf8 4885c0 }
            // n = 7, score = 100
            //   4c8d0de9db0200       | dec                 eax
            //   b905000000           | lea                 eax, [0x1e86b]
            //   4c8d05d5db0200       | dec                 eax
            //   488d155ec30200       | mov                 ebx, ecx
            //   e8????????           |                     
            //   488bf8               | dec                 eax
            //   4885c0               | mov                 dword ptr [ecx], eax

    condition:
        7 of them and filesize < 736256
}