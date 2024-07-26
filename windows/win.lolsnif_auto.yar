rule win_lolsnif_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lolsnif."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lolsnif"
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
        $sequence_0 = { 6837010000 ebc7 3bf3 0f8439060000 ff7508 56 ff15???????? }
            // n = 7, score = 200
            //   6837010000           | push                0x137
            //   ebc7                 | jmp                 0xffffffc9
            //   3bf3                 | cmp                 esi, ebx
            //   0f8439060000         | je                  0x63f
            //   ff7508               | push                dword ptr [ebp + 8]
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_1 = { 8bf0 891d???????? e9???????? e8???????? eb7a 53 }
            // n = 6, score = 200
            //   8bf0                 | mov                 esi, eax
            //   891d????????         |                     
            //   e9????????           |                     
            //   e8????????           |                     
            //   eb7a                 | jmp                 0x7c
            //   53                   | push                ebx

        $sequence_2 = { 68???????? e8???????? 5f 5e c3 ff15???????? 83f8ff }
            // n = 7, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_3 = { eb6d 56 e8???????? eb05 }
            // n = 4, score = 200
            //   eb6d                 | jmp                 0x6f
            //   56                   | push                esi
            //   e8????????           |                     
            //   eb05                 | jmp                 7

        $sequence_4 = { 0f85be000000 8b85e4fdffff 83660400 f6450820 8906 8d8318020000 8985e4fdffff }
            // n = 7, score = 200
            //   0f85be000000         | jne                 0xc4
            //   8b85e4fdffff         | mov                 eax, dword ptr [ebp - 0x21c]
            //   83660400             | and                 dword ptr [esi + 4], 0
            //   f6450820             | test                byte ptr [ebp + 8], 0x20
            //   8906                 | mov                 dword ptr [esi], eax
            //   8d8318020000         | lea                 eax, [ebx + 0x218]
            //   8985e4fdffff         | mov                 dword ptr [ebp - 0x21c], eax

        $sequence_5 = { 8b4514 5f 5b 5d c21c00 56 57 }
            // n = 7, score = 200
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c21c00               | ret                 0x1c
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_6 = { 99 6a18 894630 8d4618 57 }
            // n = 5, score = 200
            //   99                   | cdq                 
            //   6a18                 | push                0x18
            //   894630               | mov                 dword ptr [esi + 0x30], eax
            //   8d4618               | lea                 eax, [esi + 0x18]
            //   57                   | push                edi

        $sequence_7 = { ff35???????? ffd3 ff75f8 ff15???????? 5b 8b45f4 5f }
            // n = 7, score = 200
            //   ff35????????         |                     
            //   ffd3                 | call                ebx
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   5b                   | pop                 ebx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi

        $sequence_8 = { 5d c22400 55 8bec 83ec54 53 }
            // n = 6, score = 200
            //   5d                   | pop                 ebp
            //   c22400               | ret                 0x24
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec54               | sub                 esp, 0x54
            //   53                   | push                ebx

        $sequence_9 = { 8bc6 e8???????? 85c0 89442410 7409 817d100f010000 756d }
            // n = 7, score = 200
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   7409                 | je                  0xb
            //   817d100f010000       | cmp                 dword ptr [ebp + 0x10], 0x10f
            //   756d                 | jne                 0x6f

    condition:
        7 of them and filesize < 425984
}