rule win_gameover_dga_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gameover_dga."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gameover_dga"
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
        $sequence_0 = { 59 8945f4 e8???????? 6a0f 8d55c8 59 e8???????? }
            // n = 7, score = 700
            //   59                   | pop                 ecx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   e8????????           |                     
            //   6a0f                 | push                0xf
            //   8d55c8               | lea                 edx, [ebp - 0x38]
            //   59                   | pop                 ecx
            //   e8????????           |                     

        $sequence_1 = { 6a00 8d7704 56 ff15???????? 8b472c 83c40c 894718 }
            // n = 7, score = 700
            //   6a00                 | push                0
            //   8d7704               | lea                 esi, [edi + 4]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b472c               | mov                 eax, dword ptr [edi + 0x2c]
            //   83c40c               | add                 esp, 0xc
            //   894718               | mov                 dword ptr [edi + 0x18], eax

        $sequence_2 = { bf???????? 57 ffd6 f605????????01 7516 e8???????? }
            // n = 6, score = 700
            //   bf????????           |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   f605????????01       |                     
            //   7516                 | jne                 0x18
            //   e8????????           |                     

        $sequence_3 = { 83c40c 8bcf e8???????? 8b442414 48 892b }
            // n = 6, score = 700
            //   83c40c               | add                 esp, 0xc
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   48                   | dec                 eax
            //   892b                 | mov                 dword ptr [ebx], ebp

        $sequence_4 = { 8bf8 e8???????? 6aff 8d55e4 8bcf e8???????? 85c0 }
            // n = 7, score = 700
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   6aff                 | push                -1
            //   8d55e4               | lea                 edx, [ebp - 0x1c]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 0f85b9070000 c646160d fec5 886e03 e9???????? 80fb20 0f8451f8ffff }
            // n = 7, score = 700
            //   0f85b9070000         | jne                 0x7bf
            //   c646160d             | mov                 byte ptr [esi + 0x16], 0xd
            //   fec5                 | inc                 ch
            //   886e03               | mov                 byte ptr [esi + 3], ch
            //   e9????????           |                     
            //   80fb20               | cmp                 bl, 0x20
            //   0f8451f8ffff         | je                  0xfffff857

        $sequence_6 = { 51 56 50 ff15???????? 83c40c 8bce }
            // n = 6, score = 700
            //   51                   | push                ecx
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   8bce                 | mov                 ecx, esi

        $sequence_7 = { 7442 8b4c240c 2bc6 55 2bcf 8d6eff 03e9 }
            // n = 7, score = 700
            //   7442                 | je                  0x44
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   2bc6                 | sub                 eax, esi
            //   55                   | push                ebp
            //   2bcf                 | sub                 ecx, edi
            //   8d6eff               | lea                 ebp, [esi - 1]
            //   03e9                 | add                 ebp, ecx

        $sequence_8 = { c21400 57 8bf9 8b07 ff502c 84c0 7434 }
            // n = 7, score = 700
            //   c21400               | ret                 0x14
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   ff502c               | call                dword ptr [eax + 0x2c]
            //   84c0                 | test                al, al
            //   7434                 | je                  0x36

        $sequence_9 = { 8bc7 2bc2 8bce 50 ffd3 85c0 }
            // n = 6, score = 700
            //   8bc7                 | mov                 eax, edi
            //   2bc2                 | sub                 eax, edx
            //   8bce                 | mov                 ecx, esi
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 540672
}