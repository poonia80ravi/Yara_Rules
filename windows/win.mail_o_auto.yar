rule win_mail_o_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mail_o."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mail_o"
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
        $sequence_0 = { e8???????? 3bf8 7ca4 eb07 814b7c00020000 488b6c2430 488bcb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   3bf8                 | mov                 ecx, esi
            //   7ca4                 | lea                 ebp, [esi + 0x5b]
            //   eb07                 | dec                 eax
            //   814b7c00020000       | mov                 esi, eax
            //   488b6c2430           | dec                 eax
            //   488bcb               | test                eax, eax

        $sequence_1 = { 7316 4a8d3c28 ba40000000 482bd0 33c0 488bca 4c03e2 }
            // n = 7, score = 100
            //   7316                 | dec                 eax
            //   4a8d3c28             | mov                 dword ptr [esp + 0x60], eax
            //   ba40000000           | xor                 eax, eax
            //   482bd0               | dec                 eax
            //   33c0                 | mov                 dword ptr [esp + 0x20], 0x1010040
            //   488bca               | dec                 eax
            //   4c03e2               | mov                 edi, ecx

        $sequence_2 = { e8???????? 894308 85c0 753f 488b0b 4c8bc7 ba1f270000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   894308               | lea                 edx, [0x14d1f0]
            //   85c0                 | dec                 ecx
            //   753f                 | mov                 ecx, edi
            //   488b0b               | test                eax, eax
            //   4c8bc7               | jne                 0xb4b
            //   ba1f270000           | dec                 eax

        $sequence_3 = { e9???????? 4c8b93b8000000 488bb348160000 c7830c080000f1000000 4d85d2 742a 488b83c0000000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4c8b93b8000000       | movups              xmmword ptr [esp + 0x20], xmm0
            //   488bb348160000       | dec                 eax
            //   c7830c080000f1000000     | lea    edx, [esp + 0x20]
            //   4d85d2               | inc                 ecx
            //   742a                 | mov                 eax, 0x100
            //   488b83c0000000       | dec                 eax

        $sequence_4 = { e8???????? ba05000000 488bcf e8???????? c683c203000001 488bcb c60601 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ba05000000           | mov                 edx, edi
            //   488bcf               | dec                 eax
            //   e8????????           |                     
            //   c683c203000001       | lea                 edi, [0x17e19a]
            //   488bcb               | dec                 eax
            //   c60601               | mov                 ecx, edi

        $sequence_5 = { 741d 41b80f000000 488d0d42681700 488bd3 e8???????? 85c0 0f85c0000000 }
            // n = 7, score = 100
            //   741d                 | dec                 esp
            //   41b80f000000         | adc                 ecx, esi
            //   488d0d42681700       | dec                 eax
            //   488bd3               | mul                 dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   0f85c0000000         | cmp                 ebx, eax

        $sequence_6 = { eb78 488b8b98110000 4885c9 741c e8???????? 488b8b98110000 e8???????? }
            // n = 7, score = 100
            //   eb78                 | mov                 eax, ecx
            //   488b8b98110000       | dec                 eax
            //   4885c9               | shr                 eax, 0x1d
            //   741c                 | mov                 byte ptr [ecx + 0xa], al
            //   e8????????           |                     
            //   488b8b98110000       | dec                 ecx
            //   e8????????           |                     

        $sequence_7 = { e8???????? 488bf8 4885c0 752c 4c8d0d0c6a0b00 c744242041000000 8d5075 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bf8               | jne                 0x2fe
            //   4885c0               | xor                 eax, eax
            //   752c                 | dec                 eax
            //   4c8d0d0c6a0b00       | lea                 edx, [0xf0316]
            //   c744242041000000     | dec                 ecx
            //   8d5075               | mov                 ecx, esi

        $sequence_8 = { 488b4710 488918 48894308 eb08 48894308 48895f08 33d2 }
            // n = 7, score = 100
            //   488b4710             | mov                 eax, ebx
            //   488918               | dec                 eax
            //   48894308             | lea                 eax, [0xffec43f8]
            //   eb08                 | dec                 eax
            //   48894308             | mov                 ecx, ebp
            //   48895f08             | dec                 eax
            //   33d2                 | mov                 dword ptr [edi + 0x200], eax

        $sequence_9 = { ffc3 eb02 33db 49010f 837d0000 0f844effffff 41c6868005000000 }
            // n = 7, score = 100
            //   ffc3                 | cmp                 ecx, eax
            //   eb02                 | dec                 esp
            //   33db                 | mov                 dword ptr [ecx + 8], ecx
            //   49010f               | dec                 eax
            //   837d0000             | mov                 eax, dword ptr [esi + 8]
            //   0f844effffff         | dec                 eax
            //   41c6868005000000     | adc                 edx, 0

    condition:
        7 of them and filesize < 5985280
}