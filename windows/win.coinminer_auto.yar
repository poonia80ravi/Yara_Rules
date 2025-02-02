rule win_coinminer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.coinminer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coinminer"
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
        $sequence_0 = { 8b7c2440 e9???????? 6a00 ff742414 ffd6 ff742414 }
            // n = 6, score = 100
            //   8b7c2440             | mov                 edi, dword ptr [esp + 0x40]
            //   e9????????           |                     
            //   6a00                 | push                0
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   ffd6                 | call                esi
            //   ff742414             | push                dword ptr [esp + 0x14]

        $sequence_1 = { 8b07 2500ffffff 0fc8 29f8 01d8 ab 48 }
            // n = 7, score = 100
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   2500ffffff           | and                 eax, 0xffffff00
            //   0fc8                 | bswap               eax
            //   29f8                 | sub                 eax, edi
            //   01d8                 | add                 eax, ebx
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   48                   | dec                 eax

        $sequence_2 = { 8d7608 660fd60f 8d7f08 8b048de8a18f00 ffe0 }
            // n = 5, score = 100
            //   8d7608               | lea                 esi, [esi + 8]
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048de8a18f00       | mov                 eax, dword ptr [ecx*4 + 0x8fa1e8]
            //   ffe0                 | jmp                 eax

        $sequence_3 = { c1e706 8b0c8da05f9a00 c644390400 85f6 740c 56 e8???????? }
            // n = 7, score = 100
            //   c1e706               | shl                 edi, 6
            //   8b0c8da05f9a00       | mov                 ecx, dword ptr [ecx*4 + 0x9a5fa0]
            //   c644390400           | mov                 byte ptr [ecx + edi + 4], 0
            //   85f6                 | test                esi, esi
            //   740c                 | je                  0xe
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_4 = { 8b443474 03c7 50 ff742420 ff15???????? }
            // n = 5, score = 100
            //   8b443474             | mov                 eax, dword ptr [esp + esi + 0x74]
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ff15????????         |                     

        $sequence_5 = { 8413 d5cd 66b3d9 bb031fdc52 e2b4 c3 }
            // n = 6, score = 100
            //   8413                 | test                byte ptr [ebx], dl
            //   d5cd                 | aad                 0xcd
            //   66b3d9               | mov                 bl, 0xd9
            //   bb031fdc52           | mov                 ebx, 0x52dc1f03
            //   e2b4                 | loop                0xffffffb6
            //   c3                   | ret                 

        $sequence_6 = { 48 89f7 b900100600 b20d 48 89fb }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   89f7                 | mov                 edi, esi
            //   b900100600           | mov                 ecx, 0x61000
            //   b20d                 | mov                 dl, 0xd
            //   48                   | dec                 eax
            //   89fb                 | mov                 ebx, edi

        $sequence_7 = { 8b4c2420 e8???????? 83c410 85c0 0f841c010000 8b542440 8b4c2420 }
            // n = 7, score = 100
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   0f841c010000         | je                  0x122
            //   8b542440             | mov                 edx, dword ptr [esp + 0x40]
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]

        $sequence_8 = { 668975e8 8b45e8 40 660f1345f8 }
            // n = 4, score = 100
            //   668975e8             | mov                 word ptr [ebp - 0x18], si
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   40                   | inc                 eax
            //   660f1345f8           | movlpd              qword ptr [ebp - 8], xmm0

        $sequence_9 = { 7410 48 ffc0 8817 83e901 8a10 48 }
            // n = 7, score = 100
            //   7410                 | je                  0x12
            //   48                   | dec                 eax
            //   ffc0                 | inc                 eax
            //   8817                 | mov                 byte ptr [edi], dl
            //   83e901               | sub                 ecx, 1
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   48                   | dec                 eax

    condition:
        7 of them and filesize < 1523712
}