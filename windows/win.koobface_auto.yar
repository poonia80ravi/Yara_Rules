rule win_koobface_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.koobface."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.koobface"
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
        $sequence_0 = { 3bc3 7406 8b08 50 ff5108 8b85fcf7ffff 834dfcff }
            // n = 7, score = 100
            //   3bc3                 | cmp                 eax, ebx
            //   7406                 | je                  8
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   8b85fcf7ffff         | mov                 eax, dword ptr [ebp - 0x804]
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff

        $sequence_1 = { 56 8d4dd4 e8???????? 8b4db0 8d45d4 50 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   8b4db0               | mov                 ecx, dword ptr [ebp - 0x50]
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax

        $sequence_2 = { 899dfcfbffff 8b85f0fbffff 33c9 c645fc10 898ddcfbffff 3bc3 7417 }
            // n = 7, score = 100
            //   899dfcfbffff         | mov                 dword ptr [ebp - 0x404], ebx
            //   8b85f0fbffff         | mov                 eax, dword ptr [ebp - 0x410]
            //   33c9                 | xor                 ecx, ecx
            //   c645fc10             | mov                 byte ptr [ebp - 4], 0x10
            //   898ddcfbffff         | mov                 dword ptr [ebp - 0x424], ecx
            //   3bc3                 | cmp                 eax, ebx
            //   7417                 | je                  0x19

        $sequence_3 = { 0fb7d0 8bc2 59 c1e210 0bc2 }
            // n = 5, score = 100
            //   0fb7d0               | movzx               edx, ax
            //   8bc2                 | mov                 eax, edx
            //   59                   | pop                 ecx
            //   c1e210               | shl                 edx, 0x10
            //   0bc2                 | or                  eax, edx

        $sequence_4 = { 8d8514fcffff 50 ffb508fcffff ffb510fcffff ffb50cfcffff 53 ff7510 }
            // n = 7, score = 100
            //   8d8514fcffff         | lea                 eax, [ebp - 0x3ec]
            //   50                   | push                eax
            //   ffb508fcffff         | push                dword ptr [ebp - 0x3f8]
            //   ffb510fcffff         | push                dword ptr [ebp - 0x3f0]
            //   ffb50cfcffff         | push                dword ptr [ebp - 0x3f4]
            //   53                   | push                ebx
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_5 = { 50 ffd6 ff8568a2ffff 8d8dfca7ffff e8???????? e9???????? 68???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   ff8568a2ffff         | inc                 dword ptr [ebp - 0x5d98]
            //   8d8dfca7ffff         | lea                 ecx, [ebp - 0x5804]
            //   e8????????           |                     
            //   e9????????           |                     
            //   68????????           |                     

        $sequence_6 = { 8b45e4 8b08 53 68???????? 50 ff5114 8d45ec }
            // n = 7, score = 100
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   53                   | push                ebx
            //   68????????           |                     
            //   50                   | push                eax
            //   ff5114               | call                dword ptr [ecx + 0x14]
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_7 = { e8???????? 68???????? 57 e8???????? 83c414 3bc3 0f84d8000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   3bc3                 | cmp                 eax, ebx
            //   0f84d8000000         | je                  0xde

        $sequence_8 = { e8???????? b8???????? e9???????? 8d8de0fbffff e9???????? 8d8dd0fbffff e9???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   b8????????           |                     
            //   e9????????           |                     
            //   8d8de0fbffff         | lea                 ecx, [ebp - 0x420]
            //   e9????????           |                     
            //   8d8dd0fbffff         | lea                 ecx, [ebp - 0x430]
            //   e9????????           |                     

        $sequence_9 = { 50 e8???????? 8d856cfeffff 50 e8???????? 8d856cfeffff 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d856cfeffff         | lea                 eax, [ebp - 0x194]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d856cfeffff         | lea                 eax, [ebp - 0x194]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 368640
}