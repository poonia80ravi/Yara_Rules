rule win_proto8_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.proto8_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.proto8_rat"
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
        $sequence_0 = { e8???????? eb84 44396c247c 75e7 0fbec2 83c0b7 83f831 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   eb84                 | mov                 ecx, dword ptr [ebx + 0x48]
            //   44396c247c           | mov                 edi, dword ptr [ebx + 0x30]
            //   75e7                 | dec                 eax
            //   0fbec2               | mov                 eax, dword ptr [ecx]
            //   83c0b7               | mov                 eax, edi
            //   83f831               | dec                 eax

        $sequence_1 = { f30f7f442458 0f1000 0f11442448 0f104810 0f114c2458 4c896010 4c897018 }
            // n = 7, score = 100
            //   f30f7f442458         | nop                 word ptr [eax + eax]
            //   0f1000               | dec                 ecx
            //   0f11442448           | mov                 eax, dword ptr [edi + 0x78]
            //   0f104810             | inc                 ecx
            //   0f114c2458           | mov                 ecx, eax
            //   4c896010             | dec                 eax
            //   4c897018             | mov                 ecx, dword ptr [eax + ecx*8]

        $sequence_2 = { 8d46ff 4c89642448 458b548704 33ff 8d46fe 4c89742438 418b5c8704 }
            // n = 7, score = 100
            //   8d46ff               | cmp                 eax, ecx
            //   4c89642448           | inc                 ecx
            //   458b548704           | setne               al
            //   33ff                 | dec                 eax
            //   8d46fe               | mov                 ebx, dword ptr [esp + 0x30]
            //   4c89742438           | dec                 ebp
            //   418b5c8704           | test                eax, eax

        $sequence_3 = { 8b4320 83f802 488b5c2458 488b6c2460 0f95c0 4883c440 5f }
            // n = 7, score = 100
            //   8b4320               | dec                 eax
            //   83f802               | mov                 dword ptr [edi + 0x38], ebx
            //   488b5c2458           | dec                 eax
            //   488b6c2460           | lea                 ecx, [eax + ebx]
            //   0f95c0               | mov                 ecx, dword ptr [edi + 0x4c]
            //   4883c440             | dec                 esp
            //   5f                   | lea                 eax, [0x36fff]

        $sequence_4 = { 4903ce 448bc0 eb0e 492bd6 4d8bc6 4803942408010000 4803cb }
            // n = 7, score = 100
            //   4903ce               | mov                 eax, ebp
            //   448bc0               | dec                 eax
            //   eb0e                 | mov                 esi, eax
            //   492bd6               | dec                 eax
            //   4d8bc6               | test                eax, eax
            //   4803942408010000     | je                  0xbfa
            //   4803cb               | dec                 esp

        $sequence_5 = { ff5718 4489a7c8d20000 33c0 488b4c2458 4833cc e8???????? 488b9c24b8000000 }
            // n = 7, score = 100
            //   ff5718               | or                  eax, 0x80070000
            //   4489a7c8d20000       | mov                 edx, eax
            //   33c0                 | dec                 eax
            //   488b4c2458           | lea                 ecx, [ebp + 0x80]
            //   4833cc               | test                eax, eax
            //   e8????????           |                     
            //   488b9c24b8000000     | jle                 0xbf0

        $sequence_6 = { 7408 488bcb e8???????? b001 4883c420 5b c3 }
            // n = 7, score = 100
            //   7408                 | dec                 esp
            //   488bcb               | lea                 ecx, [0x2b0a6]
            //   e8????????           |                     
            //   b001                 | dec                 esp
            //   4883c420             | sub                 ecx, edx
            //   5b                   | inc                 ecx
            //   c3                   | mov                 eax, 0x10

        $sequence_7 = { 7566 488b4d60 488d047f 48c1e004 4a03443930 8b4818 83f901 }
            // n = 7, score = 100
            //   7566                 | jb                  0x32f
            //   488b4d60             | dec                 eax
            //   488d047f             | add                 edx, 0x27
            //   48c1e004             | jb                  0x34b
            //   4a03443930           | dec                 eax
            //   8b4818               | inc                 edx
            //   83f901               | dec                 eax

        $sequence_8 = { ff5318 834b6804 4c892f 498bfd e9???????? 4883f805 7322 }
            // n = 7, score = 100
            //   ff5318               | je                  0x996
            //   834b6804             | test                eax, eax
            //   4c892f               | je                  0x867
            //   498bfd               | cmp                 dword ptr [esp + 0x78], ebx
            //   e9????????           |                     
            //   4883f805             | jne                 0x7c4
            //   7322                 | dec                 eax

        $sequence_9 = { 8364242000 41ffd2 8bd8 85c0 7414 3d12030900 740d }
            // n = 7, score = 100
            //   8364242000           | jne                 0x255
            //   41ffd2               | dec                 eax
            //   8bd8                 | lea                 edx, [0x3d45b]
            //   85c0                 | dec                 eax
            //   7414                 | test                eax, eax
            //   3d12030900           | je                  0x268
            //   740d                 | inc                 ecx

    condition:
        7 of them and filesize < 2537472
}