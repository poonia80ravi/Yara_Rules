rule win_flying_dutchman_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.flying_dutchman."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flying_dutchman"
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
        $sequence_0 = { 50 8d8560ffffff 50 8d8550ffffff 50 8d45f4 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   50                   | push                eax
            //   8d8550ffffff         | lea                 eax, [ebp - 0xb0]
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_1 = { 8b5604 8b4d0c e8???????? e8???????? }
            // n = 4, score = 100
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_2 = { e8???????? 8bf8 ff75fc e8???????? 57 897e08 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   57                   | push                edi
            //   897e08               | mov                 dword ptr [esi + 8], edi
            //   e8????????           |                     

        $sequence_3 = { 2bc1 743b 2bc1 7421 2bc1 }
            // n = 5, score = 100
            //   2bc1                 | sub                 eax, ecx
            //   743b                 | je                  0x3d
            //   2bc1                 | sub                 eax, ecx
            //   7421                 | je                  0x23
            //   2bc1                 | sub                 eax, ecx

        $sequence_4 = { 8b4604 59 59 8b0e 2bc1 99 bf10020000 }
            // n = 7, score = 100
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   2bc1                 | sub                 eax, ecx
            //   99                   | cdq                 
            //   bf10020000           | mov                 edi, 0x210

        $sequence_5 = { 83c414 eb18 b8???????? 8bd3 2bd0 0fb708 66890c02 }
            // n = 7, score = 100
            //   83c414               | add                 esp, 0x14
            //   eb18                 | jmp                 0x1a
            //   b8????????           |                     
            //   8bd3                 | mov                 edx, ebx
            //   2bd0                 | sub                 edx, eax
            //   0fb708               | movzx               ecx, word ptr [eax]
            //   66890c02             | mov                 word ptr [edx + eax], cx

        $sequence_6 = { 56 8b7508 57 bbc8000000 53 6a00 bf???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   bbc8000000           | mov                 ebx, 0xc8
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   bf????????           |                     

        $sequence_7 = { 50 8d442430 64a300000000 8b1d???????? 33ff 893d???????? ff05???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d442430             | lea                 eax, [esp + 0x30]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b1d????????         |                     
            //   33ff                 | xor                 edi, edi
            //   893d????????         |                     
            //   ff05????????         |                     

        $sequence_8 = { e8???????? 8d85b8fdffff 8d4802 668b10 83c002 663bd3 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d85b8fdffff         | lea                 eax, [ebp - 0x248]
            //   8d4802               | lea                 ecx, [eax + 2]
            //   668b10               | mov                 dx, word ptr [eax]
            //   83c002               | add                 eax, 2
            //   663bd3               | cmp                 dx, bx

        $sequence_9 = { 8bf3 e8???????? 69ff10020000 033b eb0c 3b4b08 7507 }
            // n = 7, score = 100
            //   8bf3                 | mov                 esi, ebx
            //   e8????????           |                     
            //   69ff10020000         | imul                edi, edi, 0x210
            //   033b                 | add                 edi, dword ptr [ebx]
            //   eb0c                 | jmp                 0xe
            //   3b4b08               | cmp                 ecx, dword ptr [ebx + 8]
            //   7507                 | jne                 9

    condition:
        7 of them and filesize < 276480
}