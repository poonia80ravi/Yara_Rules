rule win_cabart_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.cabart."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cabart"
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
        $sequence_0 = { 8d45f8 50 ff75fc 895df8 ff15???????? }
            // n = 5, score = 300
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   ff15????????         |                     

        $sequence_1 = { 6a04 57 6a0c 6a00 a3???????? }
            // n = 5, score = 300
            //   6a04                 | push                4
            //   57                   | push                edi
            //   6a0c                 | push                0xc
            //   6a00                 | push                0
            //   a3????????           |                     

        $sequence_2 = { 6a04 57 53 6a00 a3???????? }
            // n = 5, score = 300
            //   6a04                 | push                4
            //   57                   | push                edi
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   a3????????           |                     

        $sequence_3 = { 7478 57 6800100000 bf00002000 57 }
            // n = 5, score = 300
            //   7478                 | je                  0x7a
            //   57                   | push                edi
            //   6800100000           | push                0x1000
            //   bf00002000           | mov                 edi, 0x200000
            //   57                   | push                edi

        $sequence_4 = { 6a0a 57 57 ff35???????? 57 57 }
            // n = 6, score = 300
            //   6a0a                 | push                0xa
            //   57                   | push                edi
            //   57                   | push                edi
            //   ff35????????         |                     
            //   57                   | push                edi
            //   57                   | push                edi

        $sequence_5 = { 57 6800100000 bf00002000 57 53 ff15???????? }
            // n = 6, score = 300
            //   57                   | push                edi
            //   6800100000           | push                0x1000
            //   bf00002000           | mov                 edi, 0x200000
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_6 = { 6a04 bf00100000 57 bb00020000 }
            // n = 4, score = 300
            //   6a04                 | push                4
            //   bf00100000           | mov                 edi, 0x1000
            //   57                   | push                edi
            //   bb00020000           | mov                 ebx, 0x200

        $sequence_7 = { ff15???????? 85c0 7478 57 6800100000 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7478                 | je                  0x7a
            //   57                   | push                edi
            //   6800100000           | push                0x1000

        $sequence_8 = { 85db 750a 68b90b0000 e8???????? 85ed 7507 }
            // n = 6, score = 300
            //   85db                 | test                ebx, ebx
            //   750a                 | jne                 0xc
            //   68b90b0000           | push                0xbb9
            //   e8????????           |                     
            //   85ed                 | test                ebp, ebp
            //   7507                 | jne                 9

        $sequence_9 = { 57 53 6a00 a3???????? ffd6 6a04 }
            // n = 6, score = 300
            //   57                   | push                edi
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   6a04                 | push                4

    condition:
        7 of them and filesize < 32768
}