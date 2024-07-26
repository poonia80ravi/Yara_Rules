rule win_sarhust_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sarhust."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sarhust"
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
        $sequence_0 = { e8???????? 8d8d4cffffff e8???????? 6a00 ff15???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_1 = { 8d8d4cffffff e8???????? 6a00 ff15???????? }
            // n = 4, score = 200
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_2 = { 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 8d8d4cffffff }
            // n = 5, score = 200
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]

        $sequence_3 = { 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? }
            // n = 6, score = 200
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     

        $sequence_4 = { e8???????? 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 6a00 ff15???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_5 = { 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 6a00 }
            // n = 5, score = 200
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_6 = { e8???????? 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 6a00 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_7 = { 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 6a00 ff15???????? }
            // n = 6, score = 200
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_8 = { 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 8d8d4cffffff e8???????? 6a00 }
            // n = 7, score = 200
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   8d8d4cffffff         | lea                 ecx, [ebp - 0xb4]
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_9 = { 6801000080 ff15???????? 85c0 7408 ff15???????? }
            // n = 5, score = 200
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 114688
}