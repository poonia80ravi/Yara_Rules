rule win_wmighost_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.wmighost."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wmighost"
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
        $sequence_0 = { e9???????? c745fcffffffff 8d4d84 e8???????? 8b4df4 64890d00000000 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4d84               | lea                 ecx, [ebp - 0x7c]
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_1 = { 8b4d08 51 ff15???????? 8d958cd6ffff }
            // n = 4, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d958cd6ffff         | lea                 edx, [ebp - 0x2974]

        $sequence_2 = { 7d12 68???????? 8b45e8 50 }
            // n = 4, score = 100
            //   7d12                 | jge                 0x14
            //   68????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax

        $sequence_3 = { 50 8d8df0fcffff 51 e8???????? 83c408 8b550c 52 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8df0fcffff         | lea                 ecx, [ebp - 0x310]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   52                   | push                edx

        $sequence_4 = { 83c40c 6a44 6a00 8d45b0 50 e8???????? }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   6a44                 | push                0x44
            //   6a00                 | push                0
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 837df000 7d12 68???????? 8b45e8 50 }
            // n = 5, score = 100
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   7d12                 | jge                 0x14
            //   68????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax

        $sequence_6 = { 8945b4 8b45b4 8945b0 c645fc04 8d4de8 e8???????? }
            // n = 6, score = 100
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   e8????????           |                     

        $sequence_7 = { 8945c8 8b55c8 8955e4 8b45ec }
            // n = 4, score = 100
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8b55c8               | mov                 edx, dword ptr [ebp - 0x38]
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_8 = { 50 8b4dfc 51 ff15???????? 8d958cfeffff }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d958cfeffff         | lea                 edx, [ebp - 0x174]

        $sequence_9 = { 6a00 6a00 6a00 8b55ac 52 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b55ac               | mov                 edx, dword ptr [ebp - 0x54]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 49152
}