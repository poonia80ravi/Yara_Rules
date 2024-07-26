rule win_epsilon_red_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.epsilon_red."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.epsilon_red"
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
        $sequence_0 = { 7613 31c9 31c0 e9???????? 31c0 4889d9 e8???????? }
            // n = 7, score = 200
            //   7613                 | dec                 eax
            //   31c9                 | mov                 edx, ebx
            //   31c0                 | dec                 eax
            //   e9????????           |                     
            //   31c0                 | mov                 ebx, dword ptr [esp + 0x218]
            //   4889d9               | dec                 eax
            //   e8????????           |                     

        $sequence_1 = { ebc4 83fe02 0f8480feffff 31ff e9???????? 90 90 }
            // n = 7, score = 200
            //   ebc4                 | add                 esp, ebp
            //   83fe02               | nop                 word ptr [eax + eax]
            //   0f8480feffff         | dec                 eax
            //   31ff                 | cmp                 eax, 8
            //   e9????????           |                     
            //   90                   | jge                 0x8ff
            //   90                   | inc                 esp

        $sequence_2 = { f20f10442408 f20f110424 e8???????? 488b6c2448 4883c450 c3 90 }
            // n = 7, score = 200
            //   f20f10442408         | mov                 dword ptr [eax + 0xa0], ecx
            //   f20f110424           | dec                 eax
            //   e8????????           |                     
            //   488b6c2448           | lea                 eax, [0x15ef2b]
            //   4883c450             | dec                 eax
            //   c3                   | mov                 dword ptr [esp], eax
            //   90                   | dec                 eax

        $sequence_3 = { 90 4c394b08 740b 4c89db 4d89d1 e9???????? 488b1b }
            // n = 7, score = 200
            //   90                   | mov                 ecx, dword ptr [eax + 0x30]
            //   4c394b08             | dec                 eax
            //   740b                 | lea                 ebp, [esp + 0x20]
            //   4c89db               | dec                 eax
            //   4d89d1               | lea                 eax, [0x11f0f1]
            //   e9????????           |                     
            //   488b1b               | dec                 eax

        $sequence_4 = { bb00000100 480f4cd3 4885ff 7e4e 0f1f440000 4839d7 0f8dd0010000 }
            // n = 7, score = 200
            //   bb00000100           | dec                 eax
            //   480f4cd3             | lea                 eax, [esp + 0x120]
            //   4885ff               | dec                 eax
            //   7e4e                 | mov                 dword ptr [esp], eax
            //   0f1f440000           | dec                 eax
            //   4839d7               | lea                 eax, [esp + 0x120]
            //   0f8dd0010000         | dec                 eax

        $sequence_5 = { ebcc c644242700 488b442438 48890424 e8???????? 488b6c2448 4883c450 }
            // n = 7, score = 200
            //   ebcc                 | mov                 eax, dword ptr [ecx + edi*8 + 0x10]
            //   c644242700           | dec                 esp
            //   488b442438           | add                 eax, edx
            //   48890424             | dec                 esp
            //   e8????????           |                     
            //   488b6c2448           | sub                 eax, eax
            //   4883c450             | nop                 word ptr [eax + eax]

        $sequence_6 = { eb35 4883ff20 4519c9 450fb65418ff 4989cb 4889f9 41d3e2 }
            // n = 7, score = 200
            //   eb35                 | mov                 ebx, dword ptr [esp + 0x168]
            //   4883ff20             | dec                 esp
            //   4519c9               | mov                 esp, dword ptr [esp + 0x1c0]
            //   450fb65418ff         | dec                 eax
            //   4989cb               | mov                 dword ptr [esp + 0x158], edx
            //   4889f9               | dec                 eax
            //   41d3e2               | mov                 dword ptr [esp + 0x1b8], eax

        $sequence_7 = { ebcd 488b8318040100 4829c6 4885f6 751c 31c0 4889d6 }
            // n = 7, score = 200
            //   ebcd                 | jg                  0x888
            //   488b8318040100       | dec                 esp
            //   4829c6               | mov                 edi, ebx
            //   4885f6               | dec                 ecx
            //   751c                 | cmp                 ebx, edi
            //   31c0                 | dec                 ebp
            //   4889d6               | mov                 ebp, ebx

        $sequence_8 = { f6c380 0f8475ffffff 488b9c2400010000 48891c24 488bb42408010000 4889742408 488bbc2410010000 }
            // n = 7, score = 200
            //   f6c380               | dec                 eax
            //   0f8475ffffff         | lea                 ebp, [esp + 0x30]
            //   488b9c2400010000     | dec                 eax
            //   48891c24             | mov                 ecx, dword ptr [0x28]
            //   488bb42408010000     | dec                 eax
            //   4889742408           | mov                 ecx, dword ptr [ecx]
            //   488bbc2410010000     | dec                 eax

        $sequence_9 = { 8b4808 0fc9 894c244c 8b480c 0fc9 894c2450 8b4010 }
            // n = 7, score = 200
            //   8b4808               | dec                 eax
            //   0fc9                 | mov                 ecx, dword ptr [esp + 0x380]
            //   894c244c             | dec                 eax
            //   8b480c               | lea                 edi, [0x19b355]
            //   0fc9                 | dec                 eax
            //   894c2450             | lea                 edi, [eax + 0x18]
            //   8b4010               | dec                 eax

    condition:
        7 of them and filesize < 5075968
}