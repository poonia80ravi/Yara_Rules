rule win_kingminer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.kingminer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kingminer"
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
        $sequence_0 = { ff15???????? 6a00 6a00 ff15???????? 6a01 ff15???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_1 = { ff15???????? 57 ff15???????? ff15???????? 57 ff15???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_2 = { 5d c3 a1???????? 3b05???????? 0f8d8e010000 68???????? ff15???????? }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   a1????????           |                     
            //   3b05????????         |                     
            //   0f8d8e010000         | jge                 0x194
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_3 = { 894e34 8b4d0c 895628 89462c 8b95b0feffff 89563c }
            // n = 6, score = 100
            //   894e34               | mov                 dword ptr [esi + 0x34], ecx
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   895628               | mov                 dword ptr [esi + 0x28], edx
            //   89462c               | mov                 dword ptr [esi + 0x2c], eax
            //   8b95b0feffff         | mov                 edx, dword ptr [ebp - 0x150]
            //   89563c               | mov                 dword ptr [esi + 0x3c], edx

        $sequence_4 = { 57 33ff 397e0c 7e22 90 8b4e08 833cb900 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   397e0c               | cmp                 dword ptr [esi + 0xc], edi
            //   7e22                 | jle                 0x24
            //   90                   | nop                 
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   833cb900             | cmp                 dword ptr [ecx + edi*4], 0

        $sequence_5 = { 7406 33c0 5d c21000 e8???????? }
            // n = 5, score = 100
            //   7406                 | je                  8
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   e8????????           |                     

        $sequence_6 = { 03c8 8d543112 eb5c 8d45cc 50 56 }
            // n = 6, score = 100
            //   03c8                 | add                 ecx, eax
            //   8d543112             | lea                 edx, [ecx + esi + 0x12]
            //   eb5c                 | jmp                 0x5e
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_7 = { 6a01 ff15???????? 6a00 ff15???????? 8b17 }
            // n = 5, score = 100
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8b17                 | mov                 edx, dword ptr [edi]

        $sequence_8 = { 6a00 6a00 6a00 6a00 ff15???????? 6a01 ff15???????? }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_9 = { ff15???????? 6a00 ff15???????? c3 a1???????? 3b05???????? 0f8d8e010000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   a1????????           |                     
            //   3b05????????         |                     
            //   0f8d8e010000         | jge                 0x194

    condition:
        7 of them and filesize < 165888
}