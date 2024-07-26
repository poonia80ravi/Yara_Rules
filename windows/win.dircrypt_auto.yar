rule win_dircrypt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.dircrypt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dircrypt"
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
        $sequence_0 = { c705????????01000000 e8???????? e8???????? e8???????? 833d????????00 7514 }
            // n = 6, score = 900
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7514                 | jne                 0x16

        $sequence_1 = { 6a00 e8???????? 05d6070000 50 e8???????? }
            // n = 5, score = 900
            //   6a00                 | push                0
            //   e8????????           |                     
            //   05d6070000           | add                 eax, 0x7d6
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 05d4070000 50 6a01 6a02 6a08 }
            // n = 5, score = 900
            //   05d4070000           | add                 eax, 0x7d4
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   6a08                 | push                8

        $sequence_3 = { 833d????????00 7531 c705????????01000000 e8???????? e8???????? }
            // n = 5, score = 900
            //   833d????????00       |                     
            //   7531                 | jne                 0x33
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 68???????? ff15???????? 833d????????00 751a 68???????? e8???????? }
            // n = 6, score = 900
            //   68????????           |                     
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   751a                 | jne                 0x1c
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_5 = { 50 6a01 6a02 6a08 8d45e4 50 }
            // n = 6, score = 900
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   6a08                 | push                8
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax

        $sequence_6 = { 833d????????00 751a 68???????? e8???????? 05d2070000 50 }
            // n = 6, score = 900
            //   833d????????00       |                     
            //   751a                 | jne                 0x1c
            //   68????????           |                     
            //   e8????????           |                     
            //   05d2070000           | add                 eax, 0x7d2
            //   50                   | push                eax

        $sequence_7 = { 05d3070000 50 6a01 6a02 6a08 }
            // n = 5, score = 900
            //   05d3070000           | add                 eax, 0x7d3
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   6a08                 | push                8

        $sequence_8 = { c705????????01000000 e8???????? e8???????? 833d????????00 7514 68???????? }
            // n = 6, score = 900
            //   c705????????01000000     |     
            //   e8????????           |                     
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7514                 | jne                 0x16
            //   68????????           |                     

        $sequence_9 = { e8???????? 833d????????00 7514 68???????? }
            // n = 4, score = 900
            //   e8????????           |                     
            //   833d????????00       |                     
            //   7514                 | jne                 0x16
            //   68????????           |                     

    condition:
        7 of them and filesize < 671744
}