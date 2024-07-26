rule win_keylogger_apt3_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.keylogger_apt3."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keylogger_apt3"
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
        $sequence_0 = { 89642414 68???????? e8???????? e8???????? 6a44 8d442458 }
            // n = 6, score = 300
            //   89642414             | mov                 dword ptr [esp + 0x14], esp
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   6a44                 | push                0x44
            //   8d442458             | lea                 eax, [esp + 0x58]

        $sequence_1 = { 8944243c 89442440 89442444 89442448 ff15???????? 85c0 7528 }
            // n = 7, score = 300
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   89442444             | mov                 dword ptr [esp + 0x44], eax
            //   89442448             | mov                 dword ptr [esp + 0x48], eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7528                 | jne                 0x2a

        $sequence_2 = { 0f849d000000 ff15???????? 8b2d???????? 8d4c2424 }
            // n = 4, score = 300
            //   0f849d000000         | je                  0xa3
            //   ff15????????         |                     
            //   8b2d????????         |                     
            //   8d4c2424             | lea                 ecx, [esp + 0x24]

        $sequence_3 = { 8d8eb0010000 51 83c048 50 ffd3 85c0 7436 }
            // n = 7, score = 300
            //   8d8eb0010000         | lea                 ecx, [esi + 0x1b0]
            //   51                   | push                ecx
            //   83c048               | add                 eax, 0x48
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7436                 | je                  0x38

        $sequence_4 = { 55 6a01 8d442448 6a04 50 e8???????? 83c438 }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   6a01                 | push                1
            //   8d442448             | lea                 eax, [esp + 0x48]
            //   6a04                 | push                4
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c438               | add                 esp, 0x38

        $sequence_5 = { 89442424 ff15???????? 8b4c2418 6a6c }
            // n = 4, score = 300
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   ff15????????         |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   6a6c                 | push                0x6c

        $sequence_6 = { ff15???????? 6a00 56 ff15???????? 56 ff15???????? 8b4c2438 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b4c2438             | mov                 ecx, dword ptr [esp + 0x38]

        $sequence_7 = { 8a4c2413 85ed 7e5d 8d442434 }
            // n = 4, score = 300
            //   8a4c2413             | mov                 cl, byte ptr [esp + 0x13]
            //   85ed                 | test                ebp, ebp
            //   7e5d                 | jle                 0x5f
            //   8d442434             | lea                 eax, [esp + 0x34]

        $sequence_8 = { 83f86f 7520 56 e8???????? }
            // n = 4, score = 300
            //   83f86f               | cmp                 eax, 0x6f
            //   7520                 | jne                 0x22
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_9 = { 3bc5 741e 8b15???????? 68???????? 68???????? 68???????? }
            // n = 6, score = 300
            //   3bc5                 | cmp                 eax, ebp
            //   741e                 | je                  0x20
            //   8b15????????         |                     
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     

    condition:
        7 of them and filesize < 761856
}