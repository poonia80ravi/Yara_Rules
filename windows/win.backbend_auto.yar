rule win_backbend_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.backbend."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backbend"
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
        $sequence_0 = { 83c40c 8d45f0 c745d801000000 66c745dc0500 50 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   c745d801000000       | mov                 dword ptr [ebp - 0x28], 1
            //   66c745dc0500         | mov                 word ptr [ebp - 0x24], 5
            //   50                   | push                eax

        $sequence_1 = { 50 ff15???????? 8d8500f9ffff 68???????? 50 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8500f9ffff         | lea                 eax, [ebp - 0x700]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_2 = { 8d8500f9ffff 50 e8???????? 83c424 6a01 }
            // n = 5, score = 100
            //   8d8500f9ffff         | lea                 eax, [ebp - 0x700]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   6a01                 | push                1

        $sequence_3 = { 68???????? 50 e8???????? 8d8500f9ffff 56 }
            // n = 5, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8500f9ffff         | lea                 eax, [ebp - 0x700]
            //   56                   | push                esi

        $sequence_4 = { 6830750000 ffd6 8d8500feffff 50 e8???????? 59 }
            // n = 6, score = 100
            //   6830750000           | push                0x7530
            //   ffd6                 | call                esi
            //   8d8500feffff         | lea                 eax, [ebp - 0x200]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_5 = { 90 90 90 90 bf???????? }
            // n = 5, score = 100
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   bf????????           |                     

        $sequence_6 = { ffd6 8d8500feffff 50 e8???????? 59 8d8500fbffff 50 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   8d8500feffff         | lea                 eax, [ebp - 0x200]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d8500fbffff         | lea                 eax, [ebp - 0x500]
            //   50                   | push                eax

        $sequence_7 = { 56 50 e8???????? 8d8500f9ffff }
            // n = 4, score = 100
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8500f9ffff         | lea                 eax, [ebp - 0x700]

        $sequence_8 = { 8d8d00feffff 50 50 51 57 50 }
            // n = 6, score = 100
            //   8d8d00feffff         | lea                 ecx, [ebp - 0x200]
            //   50                   | push                eax
            //   50                   | push                eax
            //   51                   | push                ecx
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_9 = { 8b35???????? 57 68???????? bf01001f00 6a00 57 ffd6 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   57                   | push                edi
            //   68????????           |                     
            //   bf01001f00           | mov                 edi, 0x1f0001
            //   6a00                 | push                0
            //   57                   | push                edi
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 49152
}