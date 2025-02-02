rule win_waterspout_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.waterspout."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.waterspout"
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
        $sequence_0 = { 8d0480 c1e005 50 ff15???????? be???????? }
            // n = 5, score = 200
            //   8d0480               | lea                 eax, [eax + eax*4]
            //   c1e005               | shl                 eax, 5
            //   50                   | push                eax
            //   ff15????????         |                     
            //   be????????           |                     

        $sequence_1 = { c684243a01000023 c684243b0100003d c684243c010000ee c684243d0100004c c684243e01000095 c684243f0100000b c684244001000042 }
            // n = 7, score = 200
            //   c684243a01000023     | mov                 byte ptr [esp + 0x13a], 0x23
            //   c684243b0100003d     | mov                 byte ptr [esp + 0x13b], 0x3d
            //   c684243c010000ee     | mov                 byte ptr [esp + 0x13c], 0xee
            //   c684243d0100004c     | mov                 byte ptr [esp + 0x13d], 0x4c
            //   c684243e01000095     | mov                 byte ptr [esp + 0x13e], 0x95
            //   c684243f0100000b     | mov                 byte ptr [esp + 0x13f], 0xb
            //   c684244001000042     | mov                 byte ptr [esp + 0x140], 0x42

        $sequence_2 = { 8d4c244c 68???????? 51 ff15???????? 8d7c2454 83c9ff 33c0 }
            // n = 7, score = 200
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d7c2454             | lea                 edi, [esp + 0x54]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { 33c0 5b 81c46c630000 c21000 a1???????? 895c2414 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   81c46c630000         | add                 esp, 0x636c
            //   c21000               | ret                 0x10
            //   a1????????           |                     
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx

        $sequence_4 = { ff15???????? 8bb42474200000 3bc7 8906 7519 8b15???????? 8b35???????? }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8bb42474200000       | mov                 esi, dword ptr [esp + 0x2074]
            //   3bc7                 | cmp                 eax, edi
            //   8906                 | mov                 dword ptr [esi], eax
            //   7519                 | jne                 0x1b
            //   8b15????????         |                     
            //   8b35????????         |                     

        $sequence_5 = { c644242001 8b54241c 52 ff15???????? 8b442420 5d 5f }
            // n = 7, score = 200
            //   c644242001           | mov                 byte ptr [esp + 0x20], 1
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi

        $sequence_6 = { 8bd6 c1ea02 8a5c142c 8b542424 2bca 83f901 }
            // n = 6, score = 200
            //   8bd6                 | mov                 edx, esi
            //   c1ea02               | shr                 edx, 2
            //   8a5c142c             | mov                 bl, byte ptr [esp + edx + 0x2c]
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   2bca                 | sub                 ecx, edx
            //   83f901               | cmp                 ecx, 1

        $sequence_7 = { 53 ffd6 a1???????? 3bc7 7409 50 ffd6 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   a1????????           |                     
            //   3bc7                 | cmp                 eax, edi
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_8 = { c68424ff0100003c c684240002000083 c684240102000053 c684240202000099 c684240302000061 c684240402000017 }
            // n = 6, score = 200
            //   c68424ff0100003c     | mov                 byte ptr [esp + 0x1ff], 0x3c
            //   c684240002000083     | mov                 byte ptr [esp + 0x200], 0x83
            //   c684240102000053     | mov                 byte ptr [esp + 0x201], 0x53
            //   c684240202000099     | mov                 byte ptr [esp + 0x202], 0x99
            //   c684240302000061     | mov                 byte ptr [esp + 0x203], 0x61
            //   c684240402000017     | mov                 byte ptr [esp + 0x204], 0x17

        $sequence_9 = { f3aa 8a842470200000 884500 7e1b 8d4eff 8bb42474200000 8bd1 }
            // n = 7, score = 200
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   8a842470200000       | mov                 al, byte ptr [esp + 0x2070]
            //   884500               | mov                 byte ptr [ebp], al
            //   7e1b                 | jle                 0x1d
            //   8d4eff               | lea                 ecx, [esi - 1]
            //   8bb42474200000       | mov                 esi, dword ptr [esp + 0x2074]
            //   8bd1                 | mov                 edx, ecx

    condition:
        7 of them and filesize < 98304
}