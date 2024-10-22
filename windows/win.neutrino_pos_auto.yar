rule win_neutrino_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.neutrino_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neutrino_pos"
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
        $sequence_0 = { 6a64 66899560ffffff 5a 6a74 66899562ffffff 8bd0 }
            // n = 6, score = 200
            //   6a64                 | push                0x64
            //   66899560ffffff       | mov                 word ptr [ebp - 0xa0], dx
            //   5a                   | pop                 edx
            //   6a74                 | push                0x74
            //   66899562ffffff       | mov                 word ptr [ebp - 0x9e], dx
            //   8bd0                 | mov                 edx, eax

        $sequence_1 = { 68b9b40c2a 56 8945fc e8???????? 59 59 57 }
            // n = 7, score = 200
            //   68b9b40c2a           | push                0x2a0cb4b9
            //   56                   | push                esi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   57                   | push                edi

        $sequence_2 = { 55 8bec 83ec2c 57 6805010000 }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec2c               | sub                 esp, 0x2c
            //   57                   | push                edi
            //   6805010000           | push                0x105

        $sequence_3 = { 66894dd2 668945fc 33c0 668945fe 8d854cffffff 68b4000000 50 }
            // n = 7, score = 200
            //   66894dd2             | mov                 word ptr [ebp - 0x2e], cx
            //   668945fc             | mov                 word ptr [ebp - 4], ax
            //   33c0                 | xor                 eax, eax
            //   668945fe             | mov                 word ptr [ebp - 2], ax
            //   8d854cffffff         | lea                 eax, [ebp - 0xb4]
            //   68b4000000           | push                0xb4
            //   50                   | push                eax

        $sequence_4 = { 66897586 66897588 5e 6a69 6689758a 5e 6a73 }
            // n = 7, score = 200
            //   66897586             | mov                 word ptr [ebp - 0x7a], si
            //   66897588             | mov                 word ptr [ebp - 0x78], si
            //   5e                   | pop                 esi
            //   6a69                 | push                0x69
            //   6689758a             | mov                 word ptr [ebp - 0x76], si
            //   5e                   | pop                 esi
            //   6a73                 | push                0x73

        $sequence_5 = { 393d???????? 752c be???????? 68558b4d0f 6a01 e8???????? 59 }
            // n = 7, score = 200
            //   393d????????         |                     
            //   752c                 | jne                 0x2e
            //   be????????           |                     
            //   68558b4d0f           | push                0xf4d8b55
            //   6a01                 | push                1
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_6 = { 59 59 6888130000 56 ffd0 ff75e8 e8???????? }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6888130000           | push                0x1388
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     

        $sequence_7 = { 66894dd0 66894dd2 66894dd4 66894dd6 668945fc 33c0 668945fe }
            // n = 7, score = 200
            //   66894dd0             | mov                 word ptr [ebp - 0x30], cx
            //   66894dd2             | mov                 word ptr [ebp - 0x2e], cx
            //   66894dd4             | mov                 word ptr [ebp - 0x2c], cx
            //   66894dd6             | mov                 word ptr [ebp - 0x2a], cx
            //   668945fc             | mov                 word ptr [ebp - 4], ax
            //   33c0                 | xor                 eax, eax
            //   668945fe             | mov                 word ptr [ebp - 2], ax

        $sequence_8 = { e8???????? 68b30c48c1 6a01 e8???????? 83c414 8d8da8fdffff 51 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   68b30c48c1           | push                0xc1480cb3
            //   6a01                 | push                1
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8d8da8fdffff         | lea                 ecx, [ebp - 0x258]
            //   51                   | push                ecx

        $sequence_9 = { 57 ff750c ff7508 ffd0 83f802 7538 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd0                 | call                eax
            //   83f802               | cmp                 eax, 2
            //   7538                 | jne                 0x3a

    condition:
        7 of them and filesize < 188416
}