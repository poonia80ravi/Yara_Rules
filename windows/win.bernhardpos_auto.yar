rule win_bernhardpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bernhardpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bernhardpos"
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
        $sequence_0 = { 894de4 8b45e4 c1e812 83e03f 8b4d0c 034df4 }
            // n = 6, score = 200
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   c1e812               | shr                 eax, 0x12
            //   83e03f               | and                 eax, 0x3f
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   034df4               | add                 ecx, dword ptr [ebp - 0xc]

        $sequence_1 = { 50 e8???????? 83c40c 8d8570feffff 50 ff15???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8570feffff         | lea                 eax, [ebp - 0x190]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { 817dfcffffff6f 7407 33c0 e9???????? }
            // n = 4, score = 200
            //   817dfcffffff6f       | cmp                 dword ptr [ebp - 4], 0x6fffffff
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     

        $sequence_3 = { 8945fc 8b45fc 8b4d08 03483c 894df4 }
            // n = 5, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   03483c               | add                 ecx, dword ptr [eax + 0x3c]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_4 = { 8808 ebc7 5f 5e 5b }
            // n = 5, score = 200
            //   8808                 | mov                 byte ptr [eax], cl
            //   ebc7                 | jmp                 0xffffffc9
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_5 = { 833d????????00 0f84b3000000 6a24 8d85c0fbffff 50 e8???????? 83c408 }
            // n = 7, score = 200
            //   833d????????00       |                     
            //   0f84b3000000         | je                  0xb9
            //   6a24                 | push                0x24
            //   8d85c0fbffff         | lea                 eax, [ebp - 0x440]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_6 = { 83e863 5f 5e 5b }
            // n = 4, score = 200
            //   83e863               | sub                 eax, 0x63
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { e8???????? a3???????? 68b3f5fec0 a1???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   a3????????           |                     
            //   68b3f5fec0           | push                0xc0fef5b3
            //   a1????????           |                     

        $sequence_8 = { eb2c 33c0 eb2d 33c0 eb29 }
            // n = 5, score = 200
            //   eb2c                 | jmp                 0x2e
            //   33c0                 | xor                 eax, eax
            //   eb2d                 | jmp                 0x2f
            //   33c0                 | xor                 eax, eax
            //   eb29                 | jmp                 0x2b

        $sequence_9 = { 3db7000000 7508 6a00 ff15???????? 5f 5e }
            // n = 6, score = 200
            //   3db7000000           | cmp                 eax, 0xb7
            //   7508                 | jne                 0xa
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 368640
}