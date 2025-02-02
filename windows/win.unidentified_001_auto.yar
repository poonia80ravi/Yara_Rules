rule win_unidentified_001_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_001."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_001"
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
        $sequence_0 = { 56 ff928c000000 5f 85c0 7d0c }
            // n = 5, score = 100
            //   56                   | push                esi
            //   ff928c000000         | call                dword ptr [edx + 0x8c]
            //   5f                   | pop                 edi
            //   85c0                 | test                eax, eax
            //   7d0c                 | jge                 0xe

        $sequence_1 = { 893e 5f 8bc6 5e 5d c20800 56 }
            // n = 7, score = 100
            //   893e                 | mov                 dword ptr [esi], edi
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   56                   | push                esi

        $sequence_2 = { 0f84f6f9ffff 3d45475900 0f84ebf9ffff 3d55525900 0f847efbffff }
            // n = 5, score = 100
            //   0f84f6f9ffff         | je                  0xfffff9fc
            //   3d45475900           | cmp                 eax, 0x594745
            //   0f84ebf9ffff         | je                  0xfffff9f1
            //   3d55525900           | cmp                 eax, 0x595255
            //   0f847efbffff         | je                  0xfffffb84

        $sequence_3 = { 56 ff5078 85c0 7d0c 68???????? 56 50 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff5078               | call                dword ptr [eax + 0x78]
            //   85c0                 | test                eax, eax
            //   7d0c                 | jge                 0xe
            //   68????????           |                     
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_4 = { 7423 83e80c 0f8469fcffff 2dff000000 0f85a6fbffff c705????????01000000 e9???????? }
            // n = 7, score = 100
            //   7423                 | je                  0x25
            //   83e80c               | sub                 eax, 0xc
            //   0f8469fcffff         | je                  0xfffffc6f
            //   2dff000000           | sub                 eax, 0xff
            //   0f85a6fbffff         | jne                 0xfffffbac
            //   c705????????01000000     |     
            //   e9????????           |                     

        $sequence_5 = { 56 ff15???????? ff7508 56 ff15???????? 50 e8???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 56 03c0 50 ff15???????? 56 53 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   03c0                 | add                 eax, eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_7 = { 0f8c1efeffff 53 ff15???????? 8b45f0 }
            // n = 4, score = 100
            //   0f8c1efeffff         | jl                  0xfffffe24
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_8 = { ff5008 8b45f8 3bc3 7406 8b08 50 }
            // n = 6, score = 100
            //   ff5008               | call                dword ptr [eax + 8]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   3bc3                 | cmp                 eax, ebx
            //   7406                 | je                  8
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   50                   | push                eax

        $sequence_9 = { 7448 8d4510 50 68???????? ff7510 ff750c }
            // n = 6, score = 100
            //   7448                 | je                  0x4a
            //   8d4510               | lea                 eax, [ebp + 0x10]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 65536
}