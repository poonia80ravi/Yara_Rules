rule elf_satori_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects elf.satori."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.satori"
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
        $sequence_0 = { 0155d0 51 51 6894000000 6a01 e8???????? 8b4dc0 }
            // n = 7, score = 100
            //   0155d0               | add                 dword ptr [ebp - 0x30], edx
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   6894000000           | push                0x94
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]

        $sequence_1 = { 80bb3504000002 7466 50 50 68???????? ff7318 }
            // n = 6, score = 100
            //   80bb3504000002       | cmp                 byte ptr [ebx + 0x435], 2
            //   7466                 | je                  0x68
            //   50                   | push                eax
            //   50                   | push                eax
            //   68????????           |                     
            //   ff7318               | push                dword ptr [ebx + 0x18]

        $sequence_2 = { b804000000 e8???????? b908000000 ba???????? }
            // n = 4, score = 100
            //   b804000000           | mov                 eax, 4
            //   e8????????           |                     
            //   b908000000           | mov                 ecx, 8
            //   ba????????           |                     

        $sequence_3 = { 53 50 68???????? 8d842454060000 50 e8???????? 83c414 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   50                   | push                eax
            //   68????????           |                     
            //   8d842454060000       | lea                 eax, [esp + 0x654]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_4 = { e8???????? 83c410 89831c040000 40 0f848b000000 51 6800040000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   89831c040000         | mov                 dword ptr [ebx + 0x41c], eax
            //   40                   | inc                 eax
            //   0f848b000000         | je                  0x91
            //   51                   | push                ecx
            //   6800040000           | push                0x400

        $sequence_5 = { 83c41c 6a00 6a03 ff35???????? e8???????? 83c40c 80cc08 }
            // n = 7, score = 100
            //   83c41c               | add                 esp, 0x1c
            //   6a00                 | push                0
            //   6a03                 | push                3
            //   ff35????????         |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   80cc08               | or                  ah, 8

        $sequence_6 = { 89d7 56 89c6 53 51 51 6a08 }
            // n = 7, score = 100
            //   89d7                 | mov                 edi, edx
            //   56                   | push                esi
            //   89c6                 | mov                 esi, eax
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   6a08                 | push                8

        $sequence_7 = { 83c410 c7851c040000ffffffff c6853604000000 e9???????? 018524040000 a1???????? 898520040000 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   c7851c040000ffffffff     | mov    dword ptr [ebp + 0x41c], 0xffffffff
            //   c6853604000000       | mov                 byte ptr [ebp + 0x436], 0
            //   e9????????           |                     
            //   018524040000         | add                 dword ptr [ebp + 0x424], eax
            //   a1????????           |                     
            //   898520040000         | mov                 dword ptr [ebp + 0x420], eax

        $sequence_8 = { e8???????? 891c24 e8???????? 83c410 83f802 7534 8a84242c220000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83f802               | cmp                 eax, 2
            //   7534                 | jne                 0x36
            //   8a84242c220000       | mov                 al, byte ptr [esp + 0x222c]

        $sequence_9 = { ff742444 e8???????? 83c410 c6442e2800 eb30 f6c205 751a }
            // n = 7, score = 100
            //   ff742444             | push                dword ptr [esp + 0x44]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   c6442e2800           | mov                 byte ptr [esi + ebp + 0x28], 0
            //   eb30                 | jmp                 0x32
            //   f6c205               | test                dl, 5
            //   751a                 | jne                 0x1c

    condition:
        7 of them and filesize < 122880
}