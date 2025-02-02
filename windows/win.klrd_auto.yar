rule win_klrd_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.klrd."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.klrd"
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
        $sequence_0 = { 8975fc ff15???????? 56 56 6a04 56 }
            // n = 6, score = 100
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   6a04                 | push                4
            //   56                   | push                esi

        $sequence_1 = { 50 ff35???????? ff15???????? 85c0 7515 ff15???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   ff15????????         |                     

        $sequence_2 = { 68ff000000 6a00 8d85b9fcffff 50 e8???????? }
            // n = 5, score = 100
            //   68ff000000           | push                0xff
            //   6a00                 | push                0
            //   8d85b9fcffff         | lea                 eax, [ebp - 0x347]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 68???????? e8???????? 59 59 eb13 8d85e8feffff }
            // n = 6, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   eb13                 | jmp                 0x15
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]

        $sequence_4 = { 8d85c1fdffff 50 e8???????? 83c40c 83a5b0fcffff00 83a5bcfdffff00 33c0 }
            // n = 7, score = 100
            //   8d85c1fdffff         | lea                 eax, [ebp - 0x23f]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   83a5b0fcffff00       | and                 dword ptr [ebp - 0x350], 0
            //   83a5bcfdffff00       | and                 dword ptr [ebp - 0x244], 0
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 8dbdd9feffff ab ab c685c0fdffff00 }
            // n = 4, score = 100
            //   8dbdd9feffff         | lea                 edi, [ebp - 0x127]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   c685c0fdffff00       | mov                 byte ptr [ebp - 0x240], 0

        $sequence_6 = { 53 ff15???????? 3bc3 7554 6804010000 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   7554                 | jne                 0x56
            //   6804010000           | push                0x104

        $sequence_7 = { ff15???????? a3???????? 6800010000 8d85e8feffff 50 ff35???????? ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   a3????????           |                     
            //   6800010000           | push                0x100
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_8 = { 6a00 8d85c1fdffff 50 e8???????? 83c40c 83a5b0fcffff00 83a5bcfdffff00 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   8d85c1fdffff         | lea                 eax, [ebp - 0x23f]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   83a5b0fcffff00       | and                 dword ptr [ebp - 0x350], 0
            //   83a5bcfdffff00       | and                 dword ptr [ebp - 0x244], 0

        $sequence_9 = { 837d0800 0f85bc020000 817d0c04010000 740d 817d0c00010000 0f85a6020000 }
            // n = 6, score = 100
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   0f85bc020000         | jne                 0x2c2
            //   817d0c04010000       | cmp                 dword ptr [ebp + 0xc], 0x104
            //   740d                 | je                  0xf
            //   817d0c00010000       | cmp                 dword ptr [ebp + 0xc], 0x100
            //   0f85a6020000         | jne                 0x2ac

    condition:
        7 of them and filesize < 40960
}