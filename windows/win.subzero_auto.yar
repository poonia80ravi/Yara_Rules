rule win_subzero_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.subzero."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.subzero"
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
        $sequence_0 = { 894d88 448b95c4000000 8b8dc0000000 894d84 8bb5bc000000 448b9db8000000 448b8db4000000 }
            // n = 7, score = 100
            //   894d88               | mov                 ebx, dword ptr [esp + 0x38]
            //   448b95c4000000       | mov                 eax, edi
            //   8b8dc0000000         | dec                 eax
            //   894d84               | mov                 esi, dword ptr [esp + 0x40]
            //   8bb5bc000000         | dec                 eax
            //   448b9db8000000       | mov                 dword ptr [esi], ebx
            //   448b8db4000000       | xor                 edi, edi

        $sequence_1 = { e8???????? 4533c9 85c0 7407 4d8910 33c0 eb3b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4533c9               | dec                 eax
            //   85c0                 | mov                 eax, dword ptr [ecx]
            //   7407                 | dec                 eax
            //   4d8910               | mov                 eax, dword ptr [eax + 0x10]
            //   33c0                 | test                edi, edi
            //   eb3b                 | js                  0x15f0

        $sequence_2 = { b001 4c8d879c020000 84c0 4d0f44c6 ba0a000000 498bc1 ff15???????? }
            // n = 7, score = 100
            //   b001                 | dec                 eax
            //   4c8d879c020000       | mov                 dword ptr [eax + 0x20], edi
            //   84c0                 | dec                 ecx
            //   4d0f44c6             | and                 dword ptr [ecx], 0
            //   ba0a000000           | mov                 ebp, 0x8002802b
            //   498bc1               | dec                 eax
            //   ff15????????         |                     

        $sequence_3 = { 0f1f440000 4084f6 7422 b900004000 85c1 7519 }
            // n = 6, score = 100
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   4084f6               | jmp                 0x2d6
            //   7422                 | movups              xmm0, xmmword ptr [edi + 0x80]
            //   b900004000           | dec                 eax
            //   85c1                 | lea                 edx, [ebp - 0x30]
            //   7519                 | dec                 esp

        $sequence_4 = { 488903 488d0511920400 48894308 488bfb 488bc3 4889bc2488000000 4885c0 }
            // n = 7, score = 100
            //   488903               | dec                 eax
            //   488d0511920400       | mov                 ebp, edx
            //   48894308             | push                ebp
            //   488bfb               | push                esi
            //   488bc3               | push                edi
            //   4889bc2488000000     | dec                 eax
            //   4885c0               | mov                 ebp, esp

        $sequence_5 = { 488b4d18 448bc8 4c8d05763c0300 ba0c120000 e8???????? 90 e9???????? }
            // n = 7, score = 100
            //   488b4d18             | mov                 ebx, eax
            //   448bc8               | dec                 eax
            //   4c8d05763c0300       | mov                 ecx, dword ptr [esp + 0x20]
            //   ba0c120000           | dec                 eax
            //   e8????????           |                     
            //   90                   | test                ecx, ecx
            //   e9????????           |                     

        $sequence_6 = { e9???????? ba0a020000 e9???????? ba0b020000 e9???????? ba0e020000 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   ba0a020000           | inc                 esp
            //   e9????????           |                     
            //   ba0b020000           | mov                 dword ptr [esp + 0x30], edi
            //   e9????????           |                     
            //   ba0e020000           | dec                 eax
            //   e9????????           |                     

        $sequence_7 = { ff15???????? 4883c420 5b c3 b908000000 e8???????? 90 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   4883c420             | dec                 eax
            //   5b                   | mov                 eax, dword ptr [edx + 0x28]
            //   c3                   | inc                 ebp
            //   b908000000           | xor                 eax, eax
            //   e8????????           |                     
            //   90                   | dec                 eax

        $sequence_8 = { ba3d000000 e8???????? 90 e9???????? b81f85eb51 41f7ec c1fa05 }
            // n = 7, score = 100
            //   ba3d000000           | dec                 eax
            //   e8????????           |                     
            //   90                   | lea                 ecx, [esp + 0x38]
            //   e9????????           |                     
            //   b81f85eb51           | dec                 eax
            //   41f7ec               | mov                 dword ptr [esp + 0x38], eax
            //   c1fa05               | dec                 eax

        $sequence_9 = { 482139 483bce 7409 488b06 488901 48213e 488d054ff10300 }
            // n = 7, score = 100
            //   482139               | mov                 dword ptr [eax], ebx
            //   483bce               | test                eax, eax
            //   7409                 | jne                 0xf43
            //   488b06               | dec                 eax
            //   488901               | lea                 edx, [0x2c13d]
            //   48213e               | dec                 ecx
            //   488d054ff10300       | mov                 ecx, edx

    condition:
        7 of them and filesize < 1420288
}