rule win_crypt0l0cker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.crypt0l0cker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypt0l0cker"
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
        $sequence_0 = { c1c810 89442410 8bc2 c1e810 0fb6c0 8b0485e0c4a800 c1c808 }
            // n = 7, score = 100
            //   c1c810               | ror                 eax, 0x10
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8bc2                 | mov                 eax, edx
            //   c1e810               | shr                 eax, 0x10
            //   0fb6c0               | movzx               eax, al
            //   8b0485e0c4a800       | mov                 eax, dword ptr [eax*4 + 0xa8c4e0]
            //   c1c808               | ror                 eax, 8

        $sequence_1 = { 8bf0 8b442434 50 e8???????? 8b442428 50 }
            // n = 6, score = 100
            //   8bf0                 | mov                 esi, eax
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   50                   | push                eax

        $sequence_2 = { ff8330030000 eb06 ff8630010000 807f0203 0f8538010000 8d8334010000 50 }
            // n = 7, score = 100
            //   ff8330030000         | inc                 dword ptr [ebx + 0x330]
            //   eb06                 | jmp                 8
            //   ff8630010000         | inc                 dword ptr [esi + 0x130]
            //   807f0203             | cmp                 byte ptr [edi + 2], 3
            //   0f8538010000         | jne                 0x13e
            //   8d8334010000         | lea                 eax, [ebx + 0x134]
            //   50                   | push                eax

        $sequence_3 = { 8bd1 3bf0 7303 8d5101 03fa 3bfa }
            // n = 6, score = 100
            //   8bd1                 | mov                 edx, ecx
            //   3bf0                 | cmp                 esi, eax
            //   7303                 | jae                 5
            //   8d5101               | lea                 edx, [ecx + 1]
            //   03fa                 | add                 edi, edx
            //   3bfa                 | cmp                 edi, edx

        $sequence_4 = { 6a00 ff35???????? ff15???????? 45 83fd06 0f8cd9feffff 5f }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   45                   | inc                 ebp
            //   83fd06               | cmp                 ebp, 6
            //   0f8cd9feffff         | jl                  0xfffffedf
            //   5f                   | pop                 edi

        $sequence_5 = { 8d70ff 85f6 780c 393cf55845a900 741a 4e 79f4 }
            // n = 7, score = 100
            //   8d70ff               | lea                 esi, [eax - 1]
            //   85f6                 | test                esi, esi
            //   780c                 | js                  0xe
            //   393cf55845a900       | cmp                 dword ptr [esi*8 + 0xa94558], edi
            //   741a                 | je                  0x1c
            //   4e                   | dec                 esi
            //   79f4                 | jns                 0xfffffff6

        $sequence_6 = { c1e818 81f100000001 81e1000000ff 0fb60485d8c0a800 33c8 8bc2 }
            // n = 6, score = 100
            //   c1e818               | shr                 eax, 0x18
            //   81f100000001         | xor                 ecx, 0x1000000
            //   81e1000000ff         | and                 ecx, 0xff000000
            //   0fb60485d8c0a800     | movzx               eax, byte ptr [eax*4 + 0xa8c0d8]
            //   33c8                 | xor                 ecx, eax
            //   8bc2                 | mov                 eax, edx

        $sequence_7 = { 32041e 8806 3b3d???????? 72d5 8b442414 6800020000 8d8c24dc000000 }
            // n = 7, score = 100
            //   32041e               | xor                 al, byte ptr [esi + ebx]
            //   8806                 | mov                 byte ptr [esi], al
            //   3b3d????????         |                     
            //   72d5                 | jb                  0xffffffd7
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   6800020000           | push                0x200
            //   8d8c24dc000000       | lea                 ecx, [esp + 0xdc]

        $sequence_8 = { 03f0 3bf9 7301 46 03d7 3bd7 7301 }
            // n = 7, score = 100
            //   03f0                 | add                 esi, eax
            //   3bf9                 | cmp                 edi, ecx
            //   7301                 | jae                 3
            //   46                   | inc                 esi
            //   03d7                 | add                 edx, edi
            //   3bd7                 | cmp                 edx, edi
            //   7301                 | jae                 3

        $sequence_9 = { 6a14 8d45b8 50 56 ff15???????? 8dbbe8000000 33c0 }
            // n = 7, score = 100
            //   6a14                 | push                0x14
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8dbbe8000000         | lea                 edi, [ebx + 0xe8]
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 917504
}