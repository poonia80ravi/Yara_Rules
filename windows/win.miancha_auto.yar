rule win_miancha_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.miancha."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miancha"
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
        $sequence_0 = { 8b15???????? 894808 8a0d???????? 89500c 884810 }
            // n = 5, score = 200
            //   8b15????????         |                     
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8a0d????????         |                     
            //   89500c               | mov                 dword ptr [eax + 0xc], edx
            //   884810               | mov                 byte ptr [eax + 0x10], cl

        $sequence_1 = { 50 56 8b35???????? 6a02 6a00 68???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_2 = { 7412 8d542418 52 ff15???????? 50 ffd6 }
            // n = 6, score = 200
            //   7412                 | je                  0x14
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_3 = { 50 56 8b35???????? 6a02 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a02                 | push                2

        $sequence_4 = { 40 50 56 8b35???????? 6a02 6a00 }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a02                 | push                2
            //   6a00                 | push                0

        $sequence_5 = { 68???????? 6a01 6a00 68???????? 51 ffd6 85c0 }
            // n = 7, score = 200
            //   68????????           |                     
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_6 = { 6a00 68???????? 52 ffd6 85c0 740b }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd

        $sequence_7 = { 8b35???????? 6a02 6a00 68???????? }
            // n = 4, score = 200
            //   8b35????????         |                     
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_8 = { 8b35???????? 6a02 6a00 68???????? 52 ffd6 85c0 }
            // n = 7, score = 200
            //   8b35????????         |                     
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_9 = { 68???????? 68???????? c744242000000000 ff15???????? 50 ff15???????? 8bf0 }
            // n = 7, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

    condition:
        7 of them and filesize < 376832
}