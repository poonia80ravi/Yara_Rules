rule win_webc2_head_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webc2_head."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_head"
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
        $sequence_0 = { 5b 81c46c010000 c3 395c240c 7474 }
            // n = 5, score = 100
            //   5b                   | pop                 ebx
            //   81c46c010000         | add                 esp, 0x16c
            //   c3                   | ret                 
            //   395c240c             | cmp                 dword ptr [esp + 0xc], ebx
            //   7474                 | je                  0x76

        $sequence_1 = { e8???????? 83c410 8d4c2418 8d942444080000 03f0 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   8d942444080000       | lea                 edx, [esp + 0x844]
            //   03f0                 | add                 esi, eax

        $sequence_2 = { 55 ffd3 85c0 74e9 6a00 }
            // n = 5, score = 100
            //   55                   | push                ebp
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   74e9                 | je                  0xffffffeb
            //   6a00                 | push                0

        $sequence_3 = { 8a440438 eb02 b03d 8b4c2410 be???????? 8d7c2438 8801 }
            // n = 7, score = 100
            //   8a440438             | mov                 al, byte ptr [esp + eax + 0x38]
            //   eb02                 | jmp                 4
            //   b03d                 | mov                 al, 0x3d
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   be????????           |                     
            //   8d7c2438             | lea                 edi, [esp + 0x38]
            //   8801                 | mov                 byte ptr [ecx], al

        $sequence_4 = { 0fb6fa 3bc7 7714 8b55fc 8a9220994000 }
            // n = 5, score = 100
            //   0fb6fa               | movzx               edi, dl
            //   3bc7                 | cmp                 eax, edi
            //   7714                 | ja                  0x16
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8a9220994000         | mov                 dl, byte ptr [edx + 0x409920]

        $sequence_5 = { 7d09 8a8c0cb8010000 eb02 b13d 0fbef9 8bc8 8bf0 }
            // n = 7, score = 100
            //   7d09                 | jge                 0xb
            //   8a8c0cb8010000       | mov                 cl, byte ptr [esp + ecx + 0x1b8]
            //   eb02                 | jmp                 4
            //   b13d                 | mov                 cl, 0x3d
            //   0fbef9               | movsx               edi, cl
            //   8bc8                 | mov                 ecx, eax
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { ff15???????? 85c0 0f840c050000 68e8030000 ff15???????? 8b542420 b980000000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f840c050000         | je                  0x512
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   b980000000           | mov                 ecx, 0x80

        $sequence_7 = { b900050000 bf???????? f3ab 8b442410 8bc8 }
            // n = 5, score = 100
            //   b900050000           | mov                 ecx, 0x500
            //   bf????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { 50 8d542430 51 52 897c244c }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d542430             | lea                 edx, [esp + 0x30]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   897c244c             | mov                 dword ptr [esp + 0x4c], edi

        $sequence_9 = { 6a1f 55 ff15???????? 8b3d???????? 6a04 81cf00330000 }
            // n = 6, score = 100
            //   6a1f                 | push                0x1f
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   6a04                 | push                4
            //   81cf00330000         | or                  edi, 0x3300

    condition:
        7 of them and filesize < 106496
}