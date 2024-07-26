rule win_unidentified_096_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_096."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_096"
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
        $sequence_0 = { 8bc1 25ffff0000 83c0d0 83f809 776a ff2485a4164000 }
            // n = 6, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   25ffff0000           | and                 eax, 0xffff
            //   83c0d0               | add                 eax, -0x30
            //   83f809               | cmp                 eax, 9
            //   776a                 | ja                  0x6c
            //   ff2485a4164000       | jmp                 dword ptr [eax*4 + 0x4016a4]

        $sequence_1 = { 59 c21000 8d54240c 6a10 }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   c21000               | ret                 0x10
            //   8d54240c             | lea                 edx, [esp + 0xc]
            //   6a10                 | push                0x10

        $sequence_2 = { ffd6 6a10 0fbfd8 ffd6 6890000000 0fbff8 ffd6 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   6a10                 | push                0x10
            //   0fbfd8               | movsx               ebx, ax
            //   ffd6                 | call                esi
            //   6890000000           | push                0x90
            //   0fbff8               | movsx               edi, ax
            //   ffd6                 | call                esi

        $sequence_3 = { 55 55 6800000080 55 }
            // n = 4, score = 100
            //   55                   | push                ebp
            //   55                   | push                ebp
            //   6800000080           | push                0x80000000
            //   55                   | push                ebp

        $sequence_4 = { 5f 83c1f8 5e 83f926 }
            // n = 4, score = 100
            //   5f                   | pop                 edi
            //   83c1f8               | add                 ecx, -8
            //   5e                   | pop                 esi
            //   83f926               | cmp                 ecx, 0x26

        $sequence_5 = { c744243000114000 896c2434 896c2438 8974243c 896c2440 896c2444 c744244806000000 }
            // n = 7, score = 100
            //   c744243000114000     | mov                 dword ptr [esp + 0x30], 0x401100
            //   896c2434             | mov                 dword ptr [esp + 0x34], ebp
            //   896c2438             | mov                 dword ptr [esp + 0x38], ebp
            //   8974243c             | mov                 dword ptr [esp + 0x3c], esi
            //   896c2440             | mov                 dword ptr [esp + 0x40], ebp
            //   896c2444             | mov                 dword ptr [esp + 0x44], ebp
            //   c744244806000000     | mov                 dword ptr [esp + 0x48], 6

        $sequence_6 = { 7735 8bd1 81e2ffff0000 83c296 }
            // n = 4, score = 100
            //   7735                 | ja                  0x37
            //   8bd1                 | mov                 edx, ecx
            //   81e2ffff0000         | and                 edx, 0xffff
            //   83c296               | add                 edx, -0x6a

        $sequence_7 = { 52 e8???????? 83c424 8b4c242a 6683f930 0f8283000000 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8b4c242a             | mov                 ecx, dword ptr [esp + 0x2a]
            //   6683f930             | cmp                 cx, 0x30
            //   0f8283000000         | jb                  0x89

        $sequence_8 = { 8ac1 2c30 a2???????? 6683f96a 723b 6683f96f }
            // n = 6, score = 100
            //   8ac1                 | mov                 al, cl
            //   2c30                 | sub                 al, 0x30
            //   a2????????           |                     
            //   6683f96a             | cmp                 cx, 0x6a
            //   723b                 | jb                  0x3d
            //   6683f96f             | cmp                 cx, 0x6f

        $sequence_9 = { 8b442422 51 8b4c2422 81e2ffff0000 }
            // n = 4, score = 100
            //   8b442422             | mov                 eax, dword ptr [esp + 0x22]
            //   51                   | push                ecx
            //   8b4c2422             | mov                 ecx, dword ptr [esp + 0x22]
            //   81e2ffff0000         | and                 edx, 0xffff

    condition:
        7 of them and filesize < 25648
}