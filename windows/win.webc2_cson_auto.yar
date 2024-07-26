rule win_webc2_cson_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webc2_cson."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_cson"
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
        $sequence_0 = { 50 8d85acfeffff 50 ff15???????? eb4d 8d85acfcffff 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   eb4d                 | jmp                 0x4f
            //   8d85acfcffff         | lea                 eax, [ebp - 0x354]
            //   50                   | push                eax

        $sequence_1 = { e9???????? 8325????????00 6a01 58 5e }
            // n = 5, score = 100
            //   e9????????           |                     
            //   8325????????00       |                     
            //   6a01                 | push                1
            //   58                   | pop                 eax
            //   5e                   | pop                 esi

        $sequence_2 = { 8bec b88c900100 e8???????? 53 }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   b88c900100           | mov                 eax, 0x1908c
            //   e8????????           |                     
            //   53                   | push                ebx

        $sequence_3 = { 8d85acfeffff 50 ff15???????? eb4d }
            // n = 4, score = 100
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   eb4d                 | jmp                 0x4f

        $sequence_4 = { ffd0 85c0 0f84a6000000 395df0 7427 68f4010000 }
            // n = 6, score = 100
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   0f84a6000000         | je                  0xac
            //   395df0               | cmp                 dword ptr [ebp - 0x10], ebx
            //   7427                 | je                  0x29
            //   68f4010000           | push                0x1f4

        $sequence_5 = { 8d85acfeffff 50 ff15???????? eb4d 8d85acfcffff }
            // n = 5, score = 100
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   eb4d                 | jmp                 0x4f
            //   8d85acfcffff         | lea                 eax, [ebp - 0x354]

        $sequence_6 = { e8???????? 6a40 8d4580 53 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   6a40                 | push                0x40
            //   8d4580               | lea                 eax, [ebp - 0x80]
            //   53                   | push                ebx

        $sequence_7 = { e8???????? 8d85746ffeff 50 e8???????? 83c420 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d85746ffeff         | lea                 eax, [ebp - 0x1908c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20

        $sequence_8 = { 895df8 c745ec0c000000 895df0 c745f401000000 ff15???????? }
            // n = 5, score = 100
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   c745ec0c000000       | mov                 dword ptr [ebp - 0x14], 0xc
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   c745f401000000       | mov                 dword ptr [ebp - 0xc], 1
            //   ff15????????         |                     

        $sequence_9 = { 8945fc 7511 ff75f8 ffd6 68???????? ff15???????? }
            // n = 6, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   7511                 | jne                 0x13
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 98304
}