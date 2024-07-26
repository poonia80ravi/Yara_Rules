rule win_doorme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.doorme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doorme"
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
        $sequence_0 = { 482bc1 4883c0f8 4883f81f 0f877e010000 e8???????? 660f6f05???????? }
            // n = 6, score = 100
            //   482bc1               | sub                 eax, 1
            //   4883c0f8             | jne                 0x54b
            //   4883f81f             | mov                 byte ptr [ecx + 0x1d], al
            //   0f877e010000         | movzx               eax, byte ptr [edx + 0x1e]
            //   e8????????           |                     
            //   660f6f05????????     |                     

        $sequence_1 = { 488910 488b4350 8908 8bc7 488b5c2440 488b742448 4883c420 }
            // n = 7, score = 100
            //   488910               | test                eax, eax
            //   488b4350             | je                  0x2f3
            //   8908                 | inc                 esp
            //   8bc7                 | mov                 eax, ebx
            //   488b5c2440           | dec                 eax
            //   488b742448           | lea                 edx, [0x16c71]
            //   4883c420             | dec                 ecx

        $sequence_2 = { c60300 488b8c2430010000 4833cc e8???????? 488b9c2460010000 4881c440010000 }
            // n = 6, score = 100
            //   c60300               | arpl                word ptr [eax + 4], cx
            //   488b8c2430010000     | lea                 edx, [ecx - 0x18]
            //   4833cc               | mov                 dword ptr [esp + ecx + 0x5c], edx
            //   e8????????           |                     
            //   488b9c2460010000     | dec                 eax
            //   4881c440010000       | lea                 eax, [0x3366a]

        $sequence_3 = { 888c2488000000 02c9 4488842480000000 44884c2478 32c8 89442408 0fb6c1 }
            // n = 7, score = 100
            //   888c2488000000       | mov                 edi, eax
            //   02c9                 | dec                 eax
            //   4488842480000000     | and                 dword ptr [eax - 0x28], 0
            //   44884c2478           | dec                 esp
            //   32c8                 | lea                 eax, [0xffffa690]
            //   89442408             | dec                 eax
            //   0fb6c1               | and                 dword ptr [eax - 0x20], 0

        $sequence_4 = { 488905???????? ff15???????? 488b0d???????? 488d1512300300 488904ca 4883c428 c3 }
            // n = 7, score = 100
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488b0d????????       |                     
            //   488d1512300300       | cmp                 edx, 0x10
            //   488904ca             | cmp                 dword ptr [ebx + 0x10], 0
            //   4883c428             | jne                 0x13b
            //   c3                   | dec                 eax

        $sequence_5 = { 488d15d9f10200 e8???????? 85c0 7421 ffc5 4883c614 3b2f }
            // n = 7, score = 100
            //   488d15d9f10200       | movzx               ebp, byte ptr [edi + 1]
            //   e8????????           |                     
            //   85c0                 | inc                 eax
            //   7421                 | xor                 dh, ch
            //   ffc5                 | xor                 al, bl
            //   4883c614             | inc                 ecx
            //   3b2f                 | xor                 al, dh

        $sequence_6 = { 488d0d206b0300 ff15???????? 488d0d1b690300 ff15???????? }
            // n = 4, score = 100
            //   488d0d206b0300       | dec                 eax
            //   ff15????????         |                     
            //   488d0d1b690300       | cmp                 eax, 0x1f
            //   ff15????????         |                     

        $sequence_7 = { c744245077270518 c744245414120404 c7442458573e134d 66c744245c5700 488bc6 90 }
            // n = 6, score = 100
            //   c744245077270518     | mov                 eax, ecx
            //   c744245414120404     | dec                 eax
            //   c7442458573e134d     | cmp                 edx, 0x1000
            //   66c744245c5700       | jb                  0x1d53
            //   488bc6               | dec                 eax
            //   90                   | mov                 ecx, dword ptr [ebp - 0x39]

        $sequence_8 = { 83f801 761e 498bc9 488d1553930200 }
            // n = 4, score = 100
            //   83f801               | mov                 ecx, ebp
            //   761e                 | and                 ecx, 0x3f
            //   498bc9               | dec                 eax
            //   488d1553930200       | shl                 ecx, 6

        $sequence_9 = { 488d41f8 4883f81f 0f8758030000 498bc8 e8???????? 49897f10 49c747180f000000 }
            // n = 7, score = 100
            //   488d41f8             | dec                 eax
            //   4883f81f             | lea                 edx, [ebx + ebp]
            //   0f8758030000         | dec                 eax
            //   498bc8               | sub                 edi, eax
            //   e8????????           |                     
            //   49897f10             | mov                 eax, ecx
            //   49c747180f000000     | xor                 ecx, ecx

    condition:
        7 of them and filesize < 580608
}