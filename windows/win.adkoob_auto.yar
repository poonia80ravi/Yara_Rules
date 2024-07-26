rule win_adkoob_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.adkoob."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adkoob"
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
        $sequence_0 = { ff37 8b54242c 8bcb 6a00 ff771c e8???????? 83c40c }
            // n = 7, score = 400
            //   ff37                 | push                dword ptr [edi]
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8bcb                 | mov                 ecx, ebx
            //   6a00                 | push                0
            //   ff771c               | push                dword ptr [edi + 0x1c]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { e8???????? e9???????? e9???????? 55 8bec 5d e9???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   e9????????           |                     
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   5d                   | pop                 ebp
            //   e9????????           |                     

        $sequence_2 = { e9???????? 6a00 ff7008 6a10 5a e8???????? 83c40c }
            // n = 7, score = 400
            //   e9????????           |                     
            //   6a00                 | push                0
            //   ff7008               | push                dword ptr [eax + 8]
            //   6a10                 | push                0x10
            //   5a                   | pop                 edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_3 = { e8???????? 8b4dd0 83c40c e9???????? 85f6 0f8496f6ffff ff759c }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8b4dd0               | mov                 ecx, dword ptr [ebp - 0x30]
            //   83c40c               | add                 esp, 0xc
            //   e9????????           |                     
            //   85f6                 | test                esi, esi
            //   0f8496f6ffff         | je                  0xfffff69c
            //   ff759c               | push                dword ptr [ebp - 0x64]

        $sequence_4 = { 6a20 5a e8???????? 83c40c 8bd6 8bcf e8???????? }
            // n = 7, score = 400
            //   6a20                 | push                0x20
            //   5a                   | pop                 edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8bd6                 | mov                 edx, esi
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_5 = { eb02 8ac3 0fb6c0 50 8d45c4 68???????? 50 }
            // n = 7, score = 400
            //   eb02                 | jmp                 4
            //   8ac3                 | mov                 al, bl
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { e8???????? 8b4de0 85c0 75cc 8b55d8 b90a010000 68199d0000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   85c0                 | test                eax, eax
            //   75cc                 | jne                 0xffffffce
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   b90a010000           | mov                 ecx, 0x10a
            //   68199d0000           | push                0x9d19

        $sequence_7 = { 8d4da8 51 8b08 e8???????? 8bce e8???????? 8b08 }
            // n = 7, score = 400
            //   8d4da8               | lea                 ecx, [ebp - 0x58]
            //   51                   | push                ecx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_8 = { e8???????? e9???????? 8b4008 8bcf 8b5db4 8bd3 8945e4 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   e9????????           |                     
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   8bcf                 | mov                 ecx, edi
            //   8b5db4               | mov                 ebx, dword ptr [ebp - 0x4c]
            //   8bd3                 | mov                 edx, ebx
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_9 = { ff702c 51 8b4c2440 e8???????? 8b542424 83c40c 8bce }
            // n = 7, score = 400
            //   ff702c               | push                dword ptr [eax + 0x2c]
            //   51                   | push                ecx
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   e8????????           |                     
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   83c40c               | add                 esp, 0xc
            //   8bce                 | mov                 ecx, esi

    condition:
        7 of them and filesize < 1867776
}