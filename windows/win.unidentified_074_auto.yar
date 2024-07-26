rule win_unidentified_074_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_074."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_074"
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
        $sequence_0 = { ff15???????? 85ff 7408 a1???????? 57 ffd0 8b4dfc }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   85ff                 | test                edi, edi
            //   7408                 | je                  0xa
            //   a1????????           |                     
            //   57                   | push                edi
            //   ffd0                 | call                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_1 = { 8d4f18 e8???????? 6800001000 c785c4feffff00000000 e8???????? }
            // n = 5, score = 200
            //   8d4f18               | lea                 ecx, [edi + 0x18]
            //   e8????????           |                     
            //   6800001000           | push                0x100000
            //   c785c4feffff00000000     | mov    dword ptr [ebp - 0x13c], 0
            //   e8????????           |                     

        $sequence_2 = { ffb570e7ffff e8???????? 33c0 c78584e7ffff07000000 c78580e7ffff00000000 66898570e7ffff }
            // n = 6, score = 200
            //   ffb570e7ffff         | push                dword ptr [ebp - 0x1890]
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c78584e7ffff07000000     | mov    dword ptr [ebp - 0x187c], 7
            //   c78580e7ffff00000000     | mov    dword ptr [ebp - 0x1880], 0
            //   66898570e7ffff       | mov                 word ptr [ebp - 0x1890], ax

        $sequence_3 = { 50 e8???????? 83c418 8d85d8f7ffff 6a00 6800010084 50 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d85d8f7ffff         | lea                 eax, [ebp - 0x828]
            //   6a00                 | push                0
            //   6800010084           | push                0x84000100
            //   50                   | push                eax

        $sequence_4 = { 50 8d8d58e7ffff e8???????? 8d85f7e6ffff c645fc08 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8d8d58e7ffff         | lea                 ecx, [ebp - 0x18a8]
            //   e8????????           |                     
            //   8d85f7e6ffff         | lea                 eax, [ebp - 0x1909]
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8

        $sequence_5 = { 668985a8dfffff 8d85c0dfffff 50 53 e8???????? }
            // n = 5, score = 200
            //   668985a8dfffff       | mov                 word ptr [ebp - 0x2058], ax
            //   8d85c0dfffff         | lea                 eax, [ebp - 0x2040]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_6 = { 7504 33c9 eb18 8d8d88e7ffff 8d5102 668b01 }
            // n = 6, score = 200
            //   7504                 | jne                 6
            //   33c9                 | xor                 ecx, ecx
            //   eb18                 | jmp                 0x1a
            //   8d8d88e7ffff         | lea                 ecx, [ebp - 0x1878]
            //   8d5102               | lea                 edx, [ecx + 2]
            //   668b01               | mov                 ax, word ptr [ecx]

        $sequence_7 = { 2bc7 c7461407000000 c7461000000000 66890e }
            // n = 4, score = 200
            //   2bc7                 | sub                 eax, edi
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   66890e               | mov                 word ptr [esi], cx

        $sequence_8 = { 8d8d58e7ffff e8???????? 8d85f7e6ffff c645fc08 50 8d85f0e6ffff 50 }
            // n = 7, score = 200
            //   8d8d58e7ffff         | lea                 ecx, [ebp - 0x18a8]
            //   e8????????           |                     
            //   8d85f7e6ffff         | lea                 eax, [ebp - 0x1909]
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   50                   | push                eax
            //   8d85f0e6ffff         | lea                 eax, [ebp - 0x1910]
            //   50                   | push                eax

        $sequence_9 = { 0f84d2000000 ff750c ffb5f0f7ffff 6a00 6a00 }
            // n = 5, score = 200
            //   0f84d2000000         | je                  0xd8
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ffb5f0f7ffff         | push                dword ptr [ebp - 0x810]
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 335872
}