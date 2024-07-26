rule win_jimmy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.jimmy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jimmy"
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
        $sequence_0 = { ff7508 ff55fc 83c414 c9 c3 55 8bec }
            // n = 7, score = 400
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff55fc               | call                dword ptr [ebp - 4]
            //   83c414               | add                 esp, 0x14
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_1 = { 8b45f0 8b4df8 0388a0000000 894de0 8b45f0 8b4df8 038880000000 }
            // n = 7, score = 400
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   0388a0000000         | add                 ecx, dword ptr [eax + 0xa0]
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   038880000000         | add                 ecx, dword ptr [eax + 0x80]

        $sequence_2 = { 8b4d10 3b481c 7308 8b4510 89459c eb09 8b4508 }
            // n = 7, score = 400
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   3b481c               | cmp                 ecx, dword ptr [eax + 0x1c]
            //   7308                 | jae                 0xa
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89459c               | mov                 dword ptr [ebp - 0x64], eax
            //   eb09                 | jmp                 0xb
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_3 = { eb02 32c0 c9 c3 55 8bec 83ec10 }
            // n = 7, score = 400
            //   eb02                 | jmp                 4
            //   32c0                 | xor                 al, al
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10

        $sequence_4 = { 8365f800 8d45f8 50 6a00 ff7508 a1???????? ffb030010000 }
            // n = 7, score = 400
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   a1????????           |                     
            //   ffb030010000         | push                dword ptr [eax + 0x130]

        $sequence_5 = { 6a04 6a00 6a01 6800000080 ff7508 e8???????? 83c41c }
            // n = 7, score = 400
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000080           | push                0x80000000
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c

        $sequence_6 = { 59 59 0fb6c0 83f801 7504 }
            // n = 5, score = 400
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   0fb6c0               | movzx               eax, al
            //   83f801               | cmp                 eax, 1
            //   7504                 | jne                 6

        $sequence_7 = { c645fb00 6a00 6880000000 6a04 6a00 6a01 }
            // n = 6, score = 400
            //   c645fb00             | mov                 byte ptr [ebp - 5], 0
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_8 = { 8b45f4 0fb700 8b4dfc 0fb709 3bc1 7514 33c0 }
            // n = 7, score = 400
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   0fb700               | movzx               eax, word ptr [eax]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   0fb709               | movzx               ecx, word ptr [ecx]
            //   3bc1                 | cmp                 eax, ecx
            //   7514                 | jne                 0x16
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { ff5024 33c0 eb20 ff75f4 a1???????? ff5040 8365f400 }
            // n = 7, score = 400
            //   ff5024               | call                dword ptr [eax + 0x24]
            //   33c0                 | xor                 eax, eax
            //   eb20                 | jmp                 0x22
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   a1????????           |                     
            //   ff5040               | call                dword ptr [eax + 0x40]
            //   8365f400             | and                 dword ptr [ebp - 0xc], 0

    condition:
        7 of them and filesize < 188416
}