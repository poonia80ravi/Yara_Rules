rule win_sanny_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sanny."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sanny"
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
        $sequence_0 = { 0344241c 8d8c08442229f4 8bc7 c1c106 }
            // n = 4, score = 100
            //   0344241c             | add                 eax, dword ptr [esp + 0x1c]
            //   8d8c08442229f4       | lea                 ecx, [eax + ecx - 0xbd6ddbc]
            //   8bc7                 | mov                 eax, edi
            //   c1c106               | rol                 ecx, 6

        $sequence_1 = { 0fb6d1 f682a185410004 7403 40 eb1a 80f92f 740f }
            // n = 7, score = 100
            //   0fb6d1               | movzx               edx, cl
            //   f682a185410004       | test                byte ptr [edx + 0x4185a1], 4
            //   7403                 | je                  5
            //   40                   | inc                 eax
            //   eb1a                 | jmp                 0x1c
            //   80f92f               | cmp                 cl, 0x2f
            //   740f                 | je                  0x11

        $sequence_2 = { 83f807 7ce9 83f907 0f859d000000 8b8558200000 83f810 0f8d8e000000 }
            // n = 7, score = 100
            //   83f807               | cmp                 eax, 7
            //   7ce9                 | jl                  0xffffffeb
            //   83f907               | cmp                 ecx, 7
            //   0f859d000000         | jne                 0xa3
            //   8b8558200000         | mov                 eax, dword ptr [ebp + 0x2058]
            //   83f810               | cmp                 eax, 0x10
            //   0f8d8e000000         | jge                 0x94

        $sequence_3 = { 83ec08 53 8b5c2414 894c2408 55 8b4c2414 8b4310 }
            // n = 7, score = 100
            //   83ec08               | sub                 esp, 8
            //   53                   | push                ebx
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   894c2408             | mov                 dword ptr [esp + 8], ecx
            //   55                   | push                ebp
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]

        $sequence_4 = { 50 8b8424280c0000 51 8b8c24280c0000 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8b8424280c0000       | mov                 eax, dword ptr [esp + 0xc28]
            //   51                   | push                ecx
            //   8b8c24280c0000       | mov                 ecx, dword ptr [esp + 0xc28]

        $sequence_5 = { f2ae f7d1 2bf9 8d9424a0020000 8bc1 8bf7 8bfa }
            // n = 7, score = 100
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8d9424a0020000       | lea                 edx, [esp + 0x2a0]
            //   8bc1                 | mov                 eax, ecx
            //   8bf7                 | mov                 esi, edi
            //   8bfa                 | mov                 edi, edx

        $sequence_6 = { c744242c34474100 c744243024474100 89742410 b920000000 33c0 8d7c2444 f3ab }
            // n = 7, score = 100
            //   c744242c34474100     | mov                 dword ptr [esp + 0x2c], 0x414734
            //   c744243024474100     | mov                 dword ptr [esp + 0x30], 0x414724
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   b920000000           | mov                 ecx, 0x20
            //   33c0                 | xor                 eax, eax
            //   8d7c2444             | lea                 edi, [esp + 0x44]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_7 = { 89442414 894c2420 0f8c98fdffff 8b5c241c 85db 0f84da000000 }
            // n = 6, score = 100
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   894c2420             | mov                 dword ptr [esp + 0x20], ecx
            //   0f8c98fdffff         | jl                  0xfffffd9e
            //   8b5c241c             | mov                 ebx, dword ptr [esp + 0x1c]
            //   85db                 | test                ebx, ebx
            //   0f84da000000         | je                  0xe0

        $sequence_8 = { 03c6 8b742434 8d8430e0e62cfe 8bf2 c1c00a 03c1 f7d6 }
            // n = 7, score = 100
            //   03c6                 | add                 eax, esi
            //   8b742434             | mov                 esi, dword ptr [esp + 0x34]
            //   8d8430e0e62cfe       | lea                 eax, [eax + esi - 0x1d31920]
            //   8bf2                 | mov                 esi, edx
            //   c1c00a               | rol                 eax, 0xa
            //   03c1                 | add                 eax, ecx
            //   f7d6                 | not                 esi

        $sequence_9 = { 8d442438 bdff7f0000 68???????? 50 896c2418 e8???????? 83c408 }
            // n = 7, score = 100
            //   8d442438             | lea                 eax, [esp + 0x38]
            //   bdff7f0000           | mov                 ebp, 0x7fff
            //   68????????           |                     
            //   50                   | push                eax
            //   896c2418             | mov                 dword ptr [esp + 0x18], ebp
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

    condition:
        7 of them and filesize < 253952
}