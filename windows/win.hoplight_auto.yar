rule win_hoplight_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hoplight."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hoplight"
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
        $sequence_0 = { 4c8b4078 ba10000000 488b442478 488bc8 }
            // n = 4, score = 100
            //   4c8b4078             | mov                 ecx, dword ptr [ecx + 0xc]
            //   ba10000000           | dec                 esp
            //   488b442478           | mov                 eax, dword ptr [eax + 0x78]
            //   488bc8               | mov                 edx, 0x10

        $sequence_1 = { 89442410 8b0424 8b4c2460 0bc8 }
            // n = 4, score = 100
            //   89442410             | cmp                 dword ptr [esp + 0x4c], 0
            //   8b0424               | jl                  0x12
            //   8b4c2460             | ja                  0x2d3
            //   0bc8                 | dec                 eax

        $sequence_2 = { 0f87cd020000 4863442438 488d0d7169feff 8b8481d8990100 }
            // n = 4, score = 100
            //   0f87cd020000         | dec                 eax
            //   4863442438           | mov                 ebp, ecx
            //   488d0d7169feff       | dec                 eax
            //   8b8481d8990100       | arpl                word ptr [ecx], cx

        $sequence_3 = { 0fb64026 8944244c 837c244c00 7c07 }
            // n = 4, score = 100
            //   0fb64026             | mov                 eax, 3
            //   8944244c             | mov                 edx, eax
            //   837c244c00           | dec                 eax
            //   7c07                 | sub                 esp, 0x20

        $sequence_4 = { 88440a58 4863442420 488b4c2460 0fb6840198000000 }
            // n = 4, score = 100
            //   88440a58             | arpl                word ptr [esp + 0x38], ax
            //   4863442420           | dec                 eax
            //   488b4c2460           | lea                 ecx, [0xfffe6971]
            //   0fb6840198000000     | mov                 eax, dword ptr [ecx + eax*4 + 0x199d8]

        $sequence_5 = { 488b442428 488b8028010000 4889442428 ebd3 }
            // n = 4, score = 100
            //   488b442428           | dec                 eax
            //   488b8028010000       | mov                 ecx, dword ptr [esp + 0x38]
            //   4889442428           | mov                 ecx, dword ptr [ecx]
            //   ebd3                 | mov                 eax, dword ptr [eax]

        $sequence_6 = { 4883ec20 488be9 486309 4533c9 }
            // n = 4, score = 100
            //   4883ec20             | dec                 eax
            //   488be9               | mov                 ecx, dword ptr [esp + 0x40]
            //   486309               | movzx               eax, word ptr [ecx + eax*4 + 0xf02]
            //   4533c9               | inc                 ecx

        $sequence_7 = { 33c8 8bc1 488b4c2420 8b490c }
            // n = 4, score = 100
            //   33c8                 | xor                 ecx, eax
            //   8bc1                 | mov                 eax, ecx
            //   488b4c2420           | dec                 eax
            //   8b490c               | mov                 ecx, dword ptr [esp + 0x20]

    condition:
        7 of them and filesize < 765952
}