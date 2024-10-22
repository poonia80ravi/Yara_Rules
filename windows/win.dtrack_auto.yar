rule win_dtrack_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.dtrack."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dtrack"
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
        $sequence_0 = { 52 8b4508 50 e8???????? 83c414 8b4d10 51 }
            // n = 7, score = 400
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   51                   | push                ecx

        $sequence_1 = { 8d8d9ffaffff 51 e8???????? 83c410 8b15???????? 52 }
            // n = 6, score = 300
            //   8d8d9ffaffff         | lea                 ecx, [ebp - 0x561]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b15????????         |                     
            //   52                   | push                edx

        $sequence_2 = { 8995e8f5ffff 8a85e8f5ffff 888587f6ffff 8b0d???????? 51 6a01 }
            // n = 6, score = 300
            //   8995e8f5ffff         | mov                 dword ptr [ebp - 0xa18], edx
            //   8a85e8f5ffff         | mov                 al, byte ptr [ebp - 0xa18]
            //   888587f6ffff         | mov                 byte ptr [ebp - 0x979], al
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   6a01                 | push                1

        $sequence_3 = { 2b8530f5ffff 8b8d30f5ffff 898d28f5ffff 898524f5ffff }
            // n = 4, score = 300
            //   2b8530f5ffff         | sub                 eax, dword ptr [ebp - 0xad0]
            //   8b8d30f5ffff         | mov                 ecx, dword ptr [ebp - 0xad0]
            //   898d28f5ffff         | mov                 dword ptr [ebp - 0xad8], ecx
            //   898524f5ffff         | mov                 dword ptr [ebp - 0xadc], eax

        $sequence_4 = { 50 ff15???????? 8d8db0f6ffff 51 ff15???????? }
            // n = 5, score = 300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8db0f6ffff         | lea                 ecx, [ebp - 0x950]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_5 = { c785ccfdffff04000000 c785ecfeffff04000000 8d85ecfeffff 50 8d8dc8fdffff 51 }
            // n = 6, score = 300
            //   c785ccfdffff04000000     | mov    dword ptr [ebp - 0x234], 4
            //   c785ecfeffff04000000     | mov    dword ptr [ebp - 0x114], 4
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   50                   | push                eax
            //   8d8dc8fdffff         | lea                 ecx, [ebp - 0x238]
            //   51                   | push                ecx

        $sequence_6 = { 8b55f0 0fb68298010000 50 8b4df0 }
            // n = 4, score = 300
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   0fb68298010000       | movzx               eax, byte ptr [edx + 0x198]
            //   50                   | push                eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_7 = { 8bb544f5ffff 8b9540f5ffff 8bca c1e902 }
            // n = 4, score = 300
            //   8bb544f5ffff         | mov                 esi, dword ptr [ebp - 0xabc]
            //   8b9540f5ffff         | mov                 edx, dword ptr [ebp - 0xac0]
            //   8bca                 | mov                 ecx, edx
            //   c1e902               | shr                 ecx, 2

        $sequence_8 = { 0bca 894d14 8b45f8 c1e018 8b4dfc c1e908 }
            // n = 6, score = 200
            //   0bca                 | or                  ecx, edx
            //   894d14               | mov                 dword ptr [ebp + 0x14], ecx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   c1e018               | shl                 eax, 0x18
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   c1e908               | shr                 ecx, 8

        $sequence_9 = { 55 8bec 83ec10 8a4514 8845f7 }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   8a4514               | mov                 al, byte ptr [ebp + 0x14]
            //   8845f7               | mov                 byte ptr [ebp - 9], al

        $sequence_10 = { 8b5508 0355f0 0fb602 0fb64df7 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0355f0               | add                 edx, dword ptr [ebp - 0x10]
            //   0fb602               | movzx               eax, byte ptr [edx]
            //   0fb64df7             | movzx               ecx, byte ptr [ebp - 9]

        $sequence_11 = { 81e2ff000000 c1e217 0bca 894d14 }
            // n = 4, score = 200
            //   81e2ff000000         | and                 edx, 0xff
            //   c1e217               | shl                 edx, 0x17
            //   0bca                 | or                  ecx, edx
            //   894d14               | mov                 dword ptr [ebp + 0x14], ecx

        $sequence_12 = { 8845f7 8b4d14 d1e9 894df8 }
            // n = 4, score = 200
            //   8845f7               | mov                 byte ptr [ebp - 9], al
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   d1e9                 | shr                 ecx, 1
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_13 = { 33d1 8855f7 8b4df8 c1e908 8b55fc d1ea 3355fc }
            // n = 7, score = 200
            //   33d1                 | xor                 edx, ecx
            //   8855f7               | mov                 byte ptr [ebp - 9], dl
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   c1e908               | shr                 ecx, 8
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   d1ea                 | shr                 edx, 1
            //   3355fc               | xor                 edx, dword ptr [ebp - 4]

        $sequence_14 = { 83c414 8b4d10 51 8b55f4 52 8b4508 }
            // n = 6, score = 200
            //   83c414               | add                 esp, 0x14
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   51                   | push                ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 1736704
}