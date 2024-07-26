rule win_fobber_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.fobber."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fobber"
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
        $sequence_0 = { e8???????? 85c0 740f 89c1 8b450c fc }
            // n = 6, score = 1100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   89c1                 | mov                 ecx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   fc                   | cld                 

        $sequence_1 = { e303 4f 89f8 5f }
            // n = 4, score = 1100
            //   e303                 | jecxz               5
            //   4f                   | dec                 edi
            //   89f8                 | mov                 eax, edi
            //   5f                   | pop                 edi

        $sequence_2 = { 66b80100 660fc146f9 6685c0 7515 0fb646f8 50 0fb746f6 }
            // n = 7, score = 1100
            //   66b80100             | mov                 ax, 1
            //   660fc146f9           | xadd                word ptr [esi - 7], ax
            //   6685c0               | test                ax, ax
            //   7515                 | jne                 0x17
            //   0fb646f8             | movzx               eax, byte ptr [esi - 8]
            //   50                   | push                eax
            //   0fb746f6             | movzx               eax, word ptr [esi - 0xa]

        $sequence_3 = { 55 89e5 31c0 50 50 ff750c }
            // n = 6, score = 1100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   31c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_4 = { 8b4d0c 3002 c0c803 0453 42 e2f6 }
            // n = 6, score = 1100
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   3002                 | xor                 byte ptr [edx], al
            //   c0c803               | ror                 al, 3
            //   0453                 | add                 al, 0x53
            //   42                   | inc                 edx
            //   e2f6                 | loop                0xfffffff8

        $sequence_5 = { 8b450c fc f2ae 31c0 e303 4f }
            // n = 6, score = 1100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   fc                   | cld                 
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   31c0                 | xor                 eax, eax
            //   e303                 | jecxz               5
            //   4f                   | dec                 edi

        $sequence_6 = { 89e5 ff7510 ff750c ff7508 e8???????? 85c0 7407 }
            // n = 7, score = 1100
            //   89e5                 | mov                 ebp, esp
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9

        $sequence_7 = { 8d4d08 51 ff31 ffd0 }
            // n = 4, score = 1100
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   51                   | push                ecx
            //   ff31                 | push                dword ptr [ecx]
            //   ffd0                 | call                eax

        $sequence_8 = { f0f266a2???????? 857f47 94 6960cf0267b974 90 c00158 }
            // n = 6, score = 100
            //   f0f266a2????????     |                     
            //   857f47               | test                dword ptr [edi + 0x47], edi
            //   94                   | xchg                eax, esp
            //   6960cf0267b974       | imul                esp, dword ptr [eax - 0x31], 0x74b96702
            //   90                   | nop                 
            //   c00158               | rol                 byte ptr [ecx], 0x58

        $sequence_9 = { f5 044d 6f b3f0 4a 46 b8ee016764 }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   044d                 | add                 al, 0x4d
            //   6f                   | outsd               dx, dword ptr [esi]
            //   b3f0                 | mov                 bl, 0xf0
            //   4a                   | dec                 edx
            //   46                   | inc                 esi
            //   b8ee016764           | mov                 eax, 0x646701ee

        $sequence_10 = { 2b4510 2d3b666f6a 8945fc 68???????? 6a0d 68???????? }
            // n = 6, score = 100
            //   2b4510               | sub                 eax, dword ptr [ebp + 0x10]
            //   2d3b666f6a           | sub                 eax, 0x6a6f663b
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   68????????           |                     
            //   6a0d                 | push                0xd
            //   68????????           |                     

        $sequence_11 = { 81c708170000 81efb1bfffff 81c7463a0000 81ef93470000 81ef8a0e0000 }
            // n = 5, score = 100
            //   81c708170000         | add                 edi, 0x1708
            //   81efb1bfffff         | sub                 edi, 0xffffbfb1
            //   81c7463a0000         | add                 edi, 0x3a46
            //   81ef93470000         | sub                 edi, 0x4793
            //   81ef8a0e0000         | sub                 edi, 0xe8a

        $sequence_12 = { 028736c8f07c 7d41 6f 01e9 339aa44cc9c2 c5fd594907 }
            // n = 6, score = 100
            //   028736c8f07c         | add                 al, byte ptr [edi + 0x7cf0c836]
            //   7d41                 | jge                 0x43
            //   6f                   | outsd               dx, dword ptr [esi]
            //   01e9                 | add                 ecx, ebp
            //   339aa44cc9c2         | xor                 ebx, dword ptr [edx - 0x3d36b35c]
            //   c5fd594907           | vmulpd              ymm1, ymm0, ymmword ptr [ecx + 7]

        $sequence_13 = { 66394118 7512 33c0 8379740e 7609 3981e8000000 }
            // n = 6, score = 100
            //   66394118             | cmp                 word ptr [ecx + 0x18], ax
            //   7512                 | jne                 0x14
            //   33c0                 | xor                 eax, eax
            //   8379740e             | cmp                 dword ptr [ecx + 0x74], 0xe
            //   7609                 | jbe                 0xb
            //   3981e8000000         | cmp                 dword ptr [ecx + 0xe8], eax

        $sequence_14 = { 81c4a8750000 81c4ab310000 81c4ad730000 81ec437b0000 }
            // n = 4, score = 100
            //   81c4a8750000         | add                 esp, 0x75a8
            //   81c4ab310000         | add                 esp, 0x31ab
            //   81c4ad730000         | add                 esp, 0x73ad
            //   81ec437b0000         | sub                 esp, 0x7b43

        $sequence_15 = { ff15???????? 8d45f8 50 68???????? 6805000080 ff15???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   68????????           |                     
            //   6805000080           | push                0x80000005
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 188416
}