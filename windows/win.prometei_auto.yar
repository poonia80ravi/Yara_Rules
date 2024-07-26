rule win_prometei_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.prometei."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
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
        $sequence_0 = { 011d???????? 03c8 8b5de4 a1???????? }
            // n = 4, score = 100
            //   011d????????         |                     
            //   03c8                 | add                 ecx, eax
            //   8b5de4               | mov                 ebx, dword ptr [ebp - 0x1c]
            //   a1????????           |                     

        $sequence_1 = { ae 60 6d b470 2b5194 }
            // n = 5, score = 100
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   60                   | pushal              
            //   6d                   | insd                dword ptr es:[edi], dx
            //   b470                 | mov                 ah, 0x70
            //   2b5194               | sub                 edx, dword ptr [ecx - 0x6c]

        $sequence_2 = { 4b 8528 d576 c4b093ae74d2 c18b315b92b5e0 }
            // n = 5, score = 100
            //   4b                   | dec                 ebx
            //   8528                 | test                dword ptr [eax], ebp
            //   d576                 | aad                 0x76
            //   c4b093ae74d2         | les                 esi, ptr [eax - 0x2d8b516d]
            //   c18b315b92b5e0       | ror                 dword ptr [ebx - 0x4a6da4cf], 0xe0

        $sequence_3 = { 014368 81434400020000 c7434000000000 83534800 }
            // n = 4, score = 100
            //   014368               | add                 dword ptr [ebx + 0x68], eax
            //   81434400020000       | add                 dword ptr [ebx + 0x44], 0x200
            //   c7434000000000       | mov                 dword ptr [ebx + 0x40], 0
            //   83534800             | adc                 dword ptr [ebx + 0x48], 0

        $sequence_4 = { 7e1f b9???????? 8ac2 0245f0 3001 }
            // n = 5, score = 100
            //   7e1f                 | jle                 0x21
            //   b9????????           |                     
            //   8ac2                 | mov                 al, dl
            //   0245f0               | add                 al, byte ptr [ebp - 0x10]
            //   3001                 | xor                 byte ptr [ecx], al

        $sequence_5 = { 4b 01c8 93 9e b2e0 e605 78a1 }
            // n = 7, score = 100
            //   4b                   | dec                 ebx
            //   01c8                 | add                 eax, ecx
            //   93                   | xchg                eax, ebx
            //   9e                   | sahf                
            //   b2e0                 | mov                 dl, 0xe0
            //   e605                 | out                 5, al
            //   78a1                 | js                  0xffffffa3

        $sequence_6 = { 014360 8b45f4 014364 8b45e4 }
            // n = 4, score = 100
            //   014360               | add                 dword ptr [ebx + 0x60], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   014364               | add                 dword ptr [ebx + 0x64], eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_7 = { f745c000020000 8bd1 0f44f8 8bc1 2bc7 2bd7 }
            // n = 6, score = 100
            //   f745c000020000       | test                dword ptr [ebp - 0x40], 0x200
            //   8bd1                 | mov                 edx, ecx
            //   0f44f8               | cmove               edi, eax
            //   8bc1                 | mov                 eax, ecx
            //   2bc7                 | sub                 eax, edi
            //   2bd7                 | sub                 edx, edi

        $sequence_8 = { 01435c 8b45fc 014360 8b45f4 }
            // n = 4, score = 100
            //   01435c               | add                 dword ptr [ebx + 0x5c], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   014360               | add                 dword ptr [ebx + 0x60], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_9 = { c1f745 c00002 0000 660f7f45b0 }
            // n = 4, score = 100
            //   c1f745               | sal                 edi, 0x45
            //   c00002               | rol                 byte ptr [eax], 2
            //   0000                 | add                 byte ptr [eax], al
            //   660f7f45b0           | movdqa              xmmword ptr [ebp - 0x50], xmm0

        $sequence_10 = { 013d???????? 8b04b5c8054400 0500080000 3bc8 }
            // n = 4, score = 100
            //   013d????????         |                     
            //   8b04b5c8054400       | mov                 eax, dword ptr [esi*4 + 0x4405c8]
            //   0500080000           | add                 eax, 0x800
            //   3bc8                 | cmp                 ecx, eax

        $sequence_11 = { 3bc7 7ce6 833d????????00 0f85cc000000 6a00 }
            // n = 5, score = 100
            //   3bc7                 | cmp                 eax, edi
            //   7ce6                 | jl                  0xffffffe8
            //   833d????????00       |                     
            //   0f85cc000000         | jne                 0xd2
            //   6a00                 | push                0

        $sequence_12 = { 014354 8b45e8 014358 8b45f0 }
            // n = 4, score = 100
            //   014354               | add                 dword ptr [ebx + 0x54], eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   014358               | add                 dword ptr [ebx + 0x58], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_13 = { 014364 8b45e4 014368 5b }
            // n = 4, score = 100
            //   014364               | add                 dword ptr [ebx + 0x64], eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   014368               | add                 dword ptr [ebx + 0x68], eax
            //   5b                   | pop                 ebx

        $sequence_14 = { 8bf3 5b 8d7db0 8907 8bc7 bf1f000000 }
            // n = 6, score = 100
            //   8bf3                 | mov                 esi, ebx
            //   5b                   | pop                 ebx
            //   8d7db0               | lea                 edi, [ebp - 0x50]
            //   8907                 | mov                 dword ptr [edi], eax
            //   8bc7                 | mov                 eax, edi
            //   bf1f000000           | mov                 edi, 0x1f

        $sequence_15 = { 014358 8b45f0 01435c 8b45fc }
            // n = 4, score = 100
            //   014358               | add                 dword ptr [ebx + 0x58], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   01435c               | add                 dword ptr [ebx + 0x5c], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 51014656
}