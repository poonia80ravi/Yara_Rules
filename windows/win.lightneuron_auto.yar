rule win_lightneuron_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lightneuron."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightneuron"
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
        $sequence_0 = { 7412 4885c9 740d c7810010000006000000 c60100 f3c3 4885c9 }
            // n = 7, score = 100
            //   7412                 | mov                 esp, ecx
            //   4885c9               | je                  0x186c
            //   740d                 | mov                 ecx, ebx
            //   c7810010000006000000     | dec    esp
            //   c60100               | mov                 esp, ecx
            //   f3c3                 | inc                 esp
            //   4885c9               | lea                 eax, [edx + 0x10]

        $sequence_1 = { 418d4d20 e8???????? 41b920000000 4d8bc7 8bd7 488bce 896c2428 }
            // n = 7, score = 100
            //   418d4d20             | mov                 byte ptr [esp + 0x108], dh
            //   e8????????           |                     
            //   41b920000000         | inc                 esp
            //   4d8bc7               | mov                 byte ptr [esp + 0x109], dh
            //   8bd7                 | inc                 esp
            //   488bce               | mov                 byte ptr [esp + 0x10a], dh
            //   896c2428             | inc                 esp

        $sequence_2 = { 0f87aa010000 48895c2460 8d5ffd 48896c2468 85db 0f8e77010000 66666666660f1f840000000000 }
            // n = 7, score = 100
            //   0f87aa010000         | imul                edx, esi
            //   48895c2460           | inc                 ecx
            //   8d5ffd               | shr                 ecx, 0x10
            //   48896c2468           | inc                 ecx
            //   85db                 | mov                 ecx, eax
            //   0f8e77010000         | inc                 ecx
            //   66666666660f1f840000000000     | mov    edx, ecx

        $sequence_3 = { 488bcb e8???????? 448b2b 41bc10000000 4c0123 4183e57f bd80000000 }
            // n = 7, score = 100
            //   488bcb               | inc                 ebp
            //   e8????????           |                     
            //   448b2b               | xor                 eax, eax
            //   41bc10000000         | dec                 eax
            //   4c0123               | mov                 ecx, ebp
            //   4183e57f             | test                eax, eax
            //   bd80000000           | mov                 dword ptr [esp + 0xa0], eax

        $sequence_4 = { 498bce e8???????? 4d85ed 7423 448b8424a0000000 33d2 }
            // n = 6, score = 100
            //   498bce               | xor                 ecx, ecx
            //   e8????????           |                     
            //   4d85ed               | mov                 edx, 0x194
            //   7423                 | mov                 ecx, 0x100000
            //   448b8424a0000000     | inc                 esp
            //   33d2                 | mov                 eax, edi

        $sequence_5 = { ff15???????? 488b8fc0000000 e8???????? 48899fc0000000 418bee 488b05???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488b8fc0000000       | inc                 ecx
            //   e8????????           |                     
            //   48899fc0000000       | mov                 eax, dword ptr [esi + ecx*4 + 0x2f7d0]
            //   418bee               | rol                 eax, 0x10
            //   488b05????????       |                     

        $sequence_6 = { 492b11 493b10 1bc0 83e0a0 c3 4983fa04 0f8c6bffffff }
            // n = 7, score = 100
            //   492b11               | test                eax, eax
            //   493b10               | jne                 0x103c
            //   1bc0                 | dec                 esp
            //   83e0a0               | mov                 eax, dword ptr [esp + 0x90]
            //   c3                   | dec                 eax
            //   4983fa04             | lea                 ecx, [esp + 0x88]
            //   0f8c6bffffff         | inc                 ecx

        $sequence_7 = { 7510 4c8b05???????? 488b05???????? eb0e 4c8b05???????? 488b05???????? 488b0f }
            // n = 7, score = 100
            //   7510                 | cmp                 dl, 0xd
            //   4c8b05????????       |                     
            //   488b05????????       |                     
            //   eb0e                 | push                ebx
            //   4c8b05????????       |                     
            //   488b05????????       |                     
            //   488b0f               | dec                 eax

        $sequence_8 = { e8???????? 448b5c2430 4c2b5c2428 4c035c2420 75e2 488d1523c80100 41b802000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   448b5c2430           | mov                 ecx, dword ptr [eax + 0x100]
            //   4c2b5c2428           | add                 edi, 8
            //   4c035c2420           | mov                 edx, edi
            //   75e2                 | dec                 eax
            //   488d1523c80100       | test                eax, eax
            //   41b802000000         | mov                 edi, dword ptr [ecx + 0x80]

        $sequence_9 = { 45335d24 c1e818 0fb6d0 8bc3 c1eb08 458b8c94c0ed0300 c1e810 }
            // n = 7, score = 100
            //   45335d24             | dec                 eax
            //   c1e818               | mov                 ebx, ecx
            //   0fb6d0               | dec                 eax
            //   8bc3                 | add                 ecx, 8
            //   c1eb08               | dec                 eax
            //   458b8c94c0ed0300     | mov                 dword ptr [esp + 0x30], edi
            //   c1e810               | cmp                 dword ptr [ebx + 0x28], 0

    condition:
        7 of them and filesize < 573440
}