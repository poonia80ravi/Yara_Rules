rule win_poscardstealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.poscardstealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poscardstealer"
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
        $sequence_0 = { 0f8cd0010000 8d049d44594200 8b48fc 8b00 2bc1 }
            // n = 5, score = 200
            //   0f8cd0010000         | jl                  0x1d6
            //   8d049d44594200       | lea                 eax, [ebx*4 + 0x425944]
            //   8b48fc               | mov                 ecx, dword ptr [eax - 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   2bc1                 | sub                 eax, ecx

        $sequence_1 = { 51 e8???????? 83c404 6a02 68???????? 8bce e8???????? }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6a02                 | push                2
            //   68????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_2 = { eb02 8bc6 c6043800 8b45ec ff45f0 40 8945ec }
            // n = 7, score = 200
            //   eb02                 | jmp                 4
            //   8bc6                 | mov                 eax, esi
            //   c6043800             | mov                 byte ptr [eax + edi], 0
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   ff45f0               | inc                 dword ptr [ebp - 0x10]
            //   40                   | inc                 eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_3 = { 033485e0794200 8b45f8 8b00 8906 8b45fc }
            // n = 5, score = 200
            //   033485e0794200       | add                 esi, dword ptr [eax*4 + 0x4279e0]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_4 = { 83ff0c 7e79 8bc7 f7d8 8945c8 eb03 8b45c8 }
            // n = 7, score = 200
            //   83ff0c               | cmp                 edi, 0xc
            //   7e79                 | jle                 0x7b
            //   8bc7                 | mov                 eax, edi
            //   f7d8                 | neg                 eax
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   eb03                 | jmp                 5
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]

        $sequence_5 = { 8d8d2cffffff e9???????? 8b8508ffffff 83e001 }
            // n = 4, score = 200
            //   8d8d2cffffff         | lea                 ecx, [ebp - 0xd4]
            //   e9????????           |                     
            //   8b8508ffffff         | mov                 eax, dword ptr [ebp - 0xf8]
            //   83e001               | and                 eax, 1

        $sequence_6 = { 83e203 83f908 7229 f3a5 ff2495c0b54000 8bc7 }
            // n = 6, score = 200
            //   83e203               | and                 edx, 3
            //   83f908               | cmp                 ecx, 8
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff2495c0b54000       | jmp                 dword ptr [edx*4 + 0x40b5c0]
            //   8bc7                 | mov                 eax, edi

        $sequence_7 = { 83c8ff 0bd0 e9???????? 8bc3 c1f805 8d0485e0794200 83e31f }
            // n = 7, score = 200
            //   83c8ff               | or                  eax, 0xffffffff
            //   0bd0                 | or                  edx, eax
            //   e9????????           |                     
            //   8bc3                 | mov                 eax, ebx
            //   c1f805               | sar                 eax, 5
            //   8d0485e0794200       | lea                 eax, [eax*4 + 0x4279e0]
            //   83e31f               | and                 ebx, 0x1f

        $sequence_8 = { e8???????? 83c420 50 8bce c645fc12 e8???????? 837de810 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   c645fc12             | mov                 byte ptr [ebp - 4], 0x12
            //   e8????????           |                     
            //   837de810             | cmp                 dword ptr [ebp - 0x18], 0x10

        $sequence_9 = { 8b0485e0794200 83e61f c1e606 8d443004 8020fe ff15???????? 50 }
            // n = 7, score = 200
            //   8b0485e0794200       | mov                 eax, dword ptr [eax*4 + 0x4279e0]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8d443004             | lea                 eax, [eax + esi + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe
            //   ff15????????         |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 362496
}