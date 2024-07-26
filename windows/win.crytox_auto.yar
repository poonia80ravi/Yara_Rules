rule win_crytox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.crytox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crytox"
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
        $sequence_0 = { e9???????? 891c24 e8???????? 8344242401 8b442424 3b4708 0f8205ffffff }
            // n = 7, score = 100
            //   e9????????           |                     
            //   891c24               | mov                 esi, eax
            //   e8????????           |                     
            //   8344242401           | mov                 eax, dword ptr [eax + 0x9910]
            //   8b442424             | mov                 eax, dword ptr [eax + 0x20]
            //   3b4708               | cmp                 byte ptr [ecx + 0xc], 0
            //   0f8205ffffff         | je                  0x719

        $sequence_1 = { eb13 83c601 81c720800000 3b742414 0f849d010000 8b93243e0200 8d0476 }
            // n = 7, score = 100
            //   eb13                 | shr                 eax, 4
            //   83c601               | shl                 eax, 4
            //   81c720800000         | jmp                 0x14b
            //   3b742414             | mov                 eax, dword ptr [ebx + 0x94]
            //   0f849d010000         | lea                 edx, [eax + 0x19]
            //   8b93243e0200         | lea                 eax, [edx + 0xf]
            //   8d0476               | shr                 eax, 4

        $sequence_2 = { e8???????? 4883f800 0f8501010000 49c7c20b91713c 488b4d90 488b95b8f6ffff 4c8d8560f7ffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4883f800             | jge                 0x6a1
            //   0f8501010000         | lea                 edi, [ebp - 1]
            //   49c7c20b91713c       | cmp                 esi, edi
            //   488b4d90             | mov                 eax, dword ptr [ebx + 0x3df0]
            //   488b95b8f6ffff       | jne                 0x64f
            //   4c8d8560f7ffff       | mov                 dword ptr [esp], eax

        $sequence_3 = { f7d8 89542424 897c2450 01d7 89442420 8d1400 c1e002 }
            // n = 7, score = 100
            //   f7d8                 | add                 ecx, eax
            //   89542424             | mov                 eax, dword ptr [esp + 0x60]
            //   897c2450             | adc                 ebx, edx
            //   01d7                 | mov                 esi, ecx
            //   89442420             | imul                dword ptr [esp + 0x10]
            //   8d1400               | mov                 edi, ebx
            //   c1e002               | imul                dword ptr [esp + 0x80]

        $sequence_4 = { e8???????? 85ff 7424 8b530c 8b4b04 8d4704 89542428 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85ff                 | mov                 eax, dword ptr [eax + 0x80]
            //   7424                 | add                 eax, 0xf4
            //   8b530c               | test                eax, eax
            //   8b4b04               | mov                 ebx, eax
            //   8d4704               | je                  0x69
            //   89542428             | mov                 dword ptr [esp + 4], ebp

        $sequence_5 = { c60300 eb7b d9c9 d95dd4 8d45f4 dd1424 89442408 }
            // n = 7, score = 100
            //   c60300               | jg                  0x19d
            //   eb7b                 | lea                 esi, [esi]
            //   d9c9                 | vmovdqu             ymm1, ymmword ptr [eax - 0x20]
            //   d95dd4               | vpavgb              ymm0, ymm0, ymmword ptr [edx]
            //   8d45f4               | vpsadbw             ymm0, ymm0, ymmword ptr [ecx]
            //   dd1424               | vpavgb              ymm1, ymm1, ymmword ptr [edx + esi]
            //   89442408             | add                 edx, edi

        $sequence_6 = { e8???????? 892c24 e8???????? 8b855caa0100 89442404 8b8558aa0100 890424 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   892c24               | lea                 esi, [esi]
            //   e8????????           |                     
            //   8b855caa0100         | mov                 dword ptr [esp + 0x18], edx
            //   89442404             | lea                 eax, [edi + edi*4]
            //   8b8558aa0100         | test                eax, eax
            //   890424               | mov                 edx, dword ptr [esp + 0x1c]

        $sequence_7 = { e8???????? 83c301 3b5c2410 0f8509ffffff e9???????? 8b442418 c744240403a00000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c301               | test                eax, eax
            //   3b5c2410             | dec                 esi
            //   0f8509ffffff         | jne                 0x36b
            //   e9????????           |                     
            //   8b442418             | cmp                 edi, 0x7c
            //   c744240403a00000     | jne                 0x396

        $sequence_8 = { e8???????? 85c0 0f840e050000 85ed 0f84d6050000 81fe27100000 0f87ab000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [esp], edi
            //   0f840e050000         | add                 esp, 0x1c
            //   85ed                 | mov                 eax, ebp
            //   0f84d6050000         | cmp                 eax, 0x10
            //   81fe27100000         | mov                 dword ptr [ebp - 0xd8], eax
            //   0f87ab000000         | jbe                 0x4e

        $sequence_9 = { f30f7e00 660f60c2 660ffdc1 660f67c0 660fd600 f30f7e4008 660f60c2 }
            // n = 7, score = 100
            //   f30f7e00             | movdqu              xmm7, xmmword ptr [edi + edx]
            //   660f60c2             | movaps              xmmword ptr [esp + 0x80], xmm7
            //   660ffdc1             | movdqu              xmm1, xmmword ptr [esi]
            //   660f67c0             | pandn               xmm6, xmm1
            //   660fd600             | movq                xmm1, qword ptr [esp + 0xd0]
            //   f30f7e4008           | pand                xmm3, xmm1
            //   660f60c2             | por                 xmm3, xmm6

    condition:
        7 of them and filesize < 6156288
}