rule win_catchamas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.catchamas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catchamas"
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
        $sequence_0 = { c744241400000000 c644241800 e8???????? 83c40c }
            // n = 4, score = 200
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   c644241800           | mov                 byte ptr [esp + 0x18], 0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 33c0 53 50 6a03 668906 ff15???????? 8bf8 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   53                   | push                ebx
            //   50                   | push                eax
            //   6a03                 | push                3
            //   668906               | mov                 word ptr [esi], ax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_2 = { ffd6 8b8c24d4010000 5f 5e 5b }
            // n = 5, score = 200
            //   ffd6                 | call                esi
            //   8b8c24d4010000       | mov                 ecx, dword ptr [esp + 0x1d4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_3 = { 51 52 8d842494100000 68???????? 50 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d842494100000       | lea                 eax, [esp + 0x1094]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_4 = { 57 68???????? ff15???????? 8bf0 85f6 7419 68???????? }
            // n = 7, score = 200
            //   57                   | push                edi
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7419                 | je                  0x1b
            //   68????????           |                     

        $sequence_5 = { ff15???????? 8d7001 56 6a40 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8d7001               | lea                 esi, [eax + 1]
            //   56                   | push                esi
            //   6a40                 | push                0x40

        $sequence_6 = { 3b5c2410 7c86 5e 5d 57 ff15???????? ff15???????? }
            // n = 7, score = 200
            //   3b5c2410             | cmp                 ebx, dword ptr [esp + 0x10]
            //   7c86                 | jl                  0xffffff88
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff15????????         |                     

        $sequence_7 = { 33c4 8984242c200000 8b842434200000 681f200000 8d4c2411 }
            // n = 5, score = 200
            //   33c4                 | xor                 eax, esp
            //   8984242c200000       | mov                 dword ptr [esp + 0x202c], eax
            //   8b842434200000       | mov                 eax, dword ptr [esp + 0x2034]
            //   681f200000           | push                0x201f
            //   8d4c2411             | lea                 ecx, [esp + 0x11]

        $sequence_8 = { c3 8d44240c 8bd0 2bf2 8a08 880c06 }
            // n = 6, score = 200
            //   c3                   | ret                 
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   8bd0                 | mov                 edx, eax
            //   2bf2                 | sub                 esi, edx
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   880c06               | mov                 byte ptr [esi + eax], cl

        $sequence_9 = { ff05???????? 68???????? ff15???????? 8b3d???????? 6a0c 56 }
            // n = 6, score = 200
            //   ff05????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   6a0c                 | push                0xc
            //   56                   | push                esi

    condition:
        7 of them and filesize < 368640
}