rule win_cryptoshield_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.cryptoshield."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptoshield"
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
        $sequence_0 = { 8bf8 33db eb0c 6a00 ff36 ff15???????? 8b18 }
            // n = 7, score = 300
            //   8bf8                 | mov                 edi, eax
            //   33db                 | xor                 ebx, ebx
            //   eb0c                 | jmp                 0xe
            //   6a00                 | push                0
            //   ff36                 | push                dword ptr [esi]
            //   ff15????????         |                     
            //   8b18                 | mov                 ebx, dword ptr [eax]

        $sequence_1 = { 8bc7 5f 5e 8913 5b 5d c3 }
            // n = 7, score = 300
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8913                 | mov                 dword ptr [ebx], edx
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_2 = { 83f801 7516 be06000000 8bc6 5e 8b4dfc }
            // n = 6, score = 300
            //   83f801               | cmp                 eax, 1
            //   7516                 | jne                 0x18
            //   be06000000           | mov                 esi, 6
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_3 = { 6a1a 8d85f0fcffff 50 6a00 ff15???????? 8d85f0fcffff }
            // n = 6, score = 300
            //   6a1a                 | push                0x1a
            //   8d85f0fcffff         | lea                 eax, [ebp - 0x310]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8d85f0fcffff         | lea                 eax, [ebp - 0x310]

        $sequence_4 = { 5d c3 8a55fa 80fa02 7405 80fa03 }
            // n = 6, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8a55fa               | mov                 dl, byte ptr [ebp - 6]
            //   80fa02               | cmp                 dl, 2
            //   7405                 | je                  7
            //   80fa03               | cmp                 dl, 3

        $sequence_5 = { 50 6a00 c785e8fbffff00000000 ff15???????? 8d85f4fdffff 50 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   6a00                 | push                0
            //   c785e8fbffff00000000     | mov    dword ptr [ebp - 0x418], 0
            //   ff15????????         |                     
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax

        $sequence_6 = { ff33 ff15???????? 8b4d0c 8b45f0 8901 }
            // n = 5, score = 300
            //   ff33                 | push                dword ptr [ebx]
            //   ff15????????         |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_7 = { 85c0 7419 ff33 ff15???????? 8b4d0c 8b45f0 }
            // n = 6, score = 300
            //   85c0                 | test                eax, eax
            //   7419                 | je                  0x1b
            //   ff33                 | push                dword ptr [ebx]
            //   ff15????????         |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_8 = { 0f45df 5f 5e 8bc3 5b 8be5 }
            // n = 6, score = 300
            //   0f45df               | cmovne              ebx, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8bc3                 | mov                 eax, ebx
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_9 = { 6a00 50 e8???????? 83c40c 8d85e4faffff 6a00 50 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d85e4faffff         | lea                 eax, [ebp - 0x51c]
            //   6a00                 | push                0
            //   50                   | push                eax

    condition:
        7 of them and filesize < 131072
}