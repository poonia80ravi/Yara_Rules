rule win_lorenz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lorenz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lorenz"
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
        $sequence_0 = { 8d45ce 898558ffffff 68ca010000 68???????? 8b8d58ffffff 0fb611 52 }
            // n = 7, score = 300
            //   8d45ce               | lea                 eax, [ebp - 0x32]
            //   898558ffffff         | mov                 dword ptr [ebp - 0xa8], eax
            //   68ca010000           | push                0x1ca
            //   68????????           |                     
            //   8b8d58ffffff         | mov                 ecx, dword ptr [ebp - 0xa8]
            //   0fb611               | movzx               edx, byte ptr [ecx]
            //   52                   | push                edx

        $sequence_1 = { 8b45a8 8b4d24 8901 8b5508 8b450c 8902 8b4d10 }
            // n = 7, score = 300
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   8b4d24               | mov                 ecx, dword ptr [ebp + 0x24]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8902                 | mov                 dword ptr [edx], eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

        $sequence_2 = { c745e800000000 c745fc00000000 e8???????? 833800 7428 e8???????? 833800 }
            // n = 7, score = 300
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   833800               | cmp                 dword ptr [eax], 0
            //   7428                 | je                  0x2a
            //   e8????????           |                     
            //   833800               | cmp                 dword ptr [eax], 0

        $sequence_3 = { 8b4d90 c6012b 8b5590 83c201 895590 8b4d10 e8???????? }
            // n = 7, score = 300
            //   8b4d90               | mov                 ecx, dword ptr [ebp - 0x70]
            //   c6012b               | mov                 byte ptr [ecx], 0x2b
            //   8b5590               | mov                 edx, dword ptr [ebp - 0x70]
            //   83c201               | add                 edx, 1
            //   895590               | mov                 dword ptr [ebp - 0x70], edx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   e8????????           |                     

        $sequence_4 = { 8d45f4 64a300000000 894dec 8b45ec 8b4808 8d540902 8955e0 }
            // n = 7, score = 300
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   8d540902             | lea                 edx, [ecx + ecx + 2]
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx

        $sequence_5 = { 8b55b0 89048a 8b45cc 83c001 8945cc ebb0 8b4dcc }
            // n = 7, score = 300
            //   8b55b0               | mov                 edx, dword ptr [ebp - 0x50]
            //   89048a               | mov                 dword ptr [edx + ecx*4], eax
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   83c001               | add                 eax, 1
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   ebb0                 | jmp                 0xffffffb2
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]

        $sequence_6 = { d96dc8 dfbd70ffffff d96df0 8b8570ffffff 8945e4 8b4dfc 8b55e4 }
            // n = 7, score = 300
            //   d96dc8               | fldcw               word ptr [ebp - 0x38]
            //   dfbd70ffffff         | fistp               qword ptr [ebp - 0x90]
            //   d96df0               | fldcw               word ptr [ebp - 0x10]
            //   8b8570ffffff         | mov                 eax, dword ptr [ebp - 0x90]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]

        $sequence_7 = { eb02 ebae 8b4dec 83b99801000000 7530 0fb655f1 85d2 }
            // n = 7, score = 300
            //   eb02                 | jmp                 4
            //   ebae                 | jmp                 0xffffffb0
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   83b99801000000       | cmp                 dword ptr [ecx + 0x198], 0
            //   7530                 | jne                 0x32
            //   0fb655f1             | movzx               edx, byte ptr [ebp - 0xf]
            //   85d2                 | test                edx, edx

        $sequence_8 = { c745fc00000000 8d4d9c e8???????? 8945ec c645f300 c745dc00000000 eb09 }
            // n = 7, score = 300
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   c645f300             | mov                 byte ptr [ebp - 0xd], 0
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   eb09                 | jmp                 0xb

        $sequence_9 = { eb07 c745cc00000000 8a55cc 8855ff c745f400000000 eb09 8b45f4 }
            // n = 7, score = 300
            //   eb07                 | jmp                 9
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0
            //   8a55cc               | mov                 dl, byte ptr [ebp - 0x34]
            //   8855ff               | mov                 byte ptr [ebp - 1], dl
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   eb09                 | jmp                 0xb
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 2254848
}