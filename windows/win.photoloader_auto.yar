rule win_photoloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.photoloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.photoloader"
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
        $sequence_0 = { c0c003 0fb6c8 8bc1 83e10f }
            // n = 4, score = 1000
            //   c0c003               | rol                 al, 3
            //   0fb6c8               | movzx               ecx, al
            //   8bc1                 | mov                 eax, ecx
            //   83e10f               | and                 ecx, 0xf

        $sequence_1 = { 7407 8b41f8 3901 7714 }
            // n = 4, score = 800
            //   7407                 | je                  9
            //   8b41f8               | mov                 eax, dword ptr [ecx - 8]
            //   3901                 | cmp                 dword ptr [ecx], eax
            //   7714                 | ja                  0x16

        $sequence_2 = { ff15???????? 25ffffff00 0d00000005 e9???????? 8bd7 397b1c }
            // n = 6, score = 800
            //   ff15????????         |                     
            //   25ffffff00           | and                 eax, 0xffffff
            //   0d00000005           | or                  eax, 0x5000000
            //   e9????????           |                     
            //   8bd7                 | mov                 edx, edi
            //   397b1c               | cmp                 dword ptr [ebx + 0x1c], edi

        $sequence_3 = { 33ff 8bf7 8d6f10 ff15???????? }
            // n = 4, score = 800
            //   33ff                 | xor                 edi, edi
            //   8bf7                 | mov                 esi, edi
            //   8d6f10               | lea                 ebp, [edi + 0x10]
            //   ff15????????         |                     

        $sequence_4 = { 85c0 0f85d2000000 ff15???????? 83f87a 0f85c3000000 8b457f }
            // n = 6, score = 800
            //   85c0                 | test                eax, eax
            //   0f85d2000000         | jne                 0xd8
            //   ff15????????         |                     
            //   83f87a               | cmp                 eax, 0x7a
            //   0f85c3000000         | jne                 0xc9
            //   8b457f               | mov                 eax, dword ptr [ebp + 0x7f]

        $sequence_5 = { 894704 33c9 b800000040 0fa2 895f0c e8???????? }
            // n = 6, score = 800
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   33c9                 | xor                 ecx, ecx
            //   b800000040           | mov                 eax, 0x40000000
            //   0fa2                 | cpuid               
            //   895f0c               | mov                 dword ptr [edi + 0xc], ebx
            //   e8????????           |                     

        $sequence_6 = { 33c9 b801000000 0fa2 89442420 895c2424 894c2428 }
            // n = 6, score = 800
            //   33c9                 | xor                 ecx, ecx
            //   b801000000           | mov                 eax, 1
            //   0fa2                 | cpuid               
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   895c2424             | mov                 dword ptr [esp + 0x24], ebx
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx

        $sequence_7 = { 8b457f 85c0 0f84b8000000 8bd8 ff15???????? }
            // n = 5, score = 800
            //   8b457f               | mov                 eax, dword ptr [ebp + 0x7f]
            //   85c0                 | test                eax, eax
            //   0f84b8000000         | je                  0xbe
            //   8bd8                 | mov                 ebx, eax
            //   ff15????????         |                     

        $sequence_8 = { 7466 03f7 803e2f 7506 }
            // n = 4, score = 200
            //   7466                 | je                  0x68
            //   03f7                 | add                 esi, edi
            //   803e2f               | cmp                 byte ptr [esi], 0x2f
            //   7506                 | jne                 8

        $sequence_9 = { 33db 85f6 0f95c3 eb02 }
            // n = 4, score = 200
            //   33db                 | xor                 ebx, ebx
            //   85f6                 | test                esi, esi
            //   0f95c3               | setne               bl
            //   eb02                 | jmp                 4

        $sequence_10 = { 33c0 eb7f 53 57 ff15???????? 8b5c2418 8903 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   eb7f                 | jmp                 0x81
            //   53                   | push                ebx
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b5c2418             | mov                 ebx, dword ptr [esp + 0x18]
            //   8903                 | mov                 dword ptr [ebx], eax

        $sequence_11 = { 50 55 8bda ff15???????? }
            // n = 4, score = 200
            //   50                   | push                eax
            //   55                   | push                ebp
            //   8bda                 | mov                 ebx, edx
            //   ff15????????         |                     

        $sequence_12 = { 51 ffd6 55 03f8 bd???????? }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   55                   | push                ebp
            //   03f8                 | add                 edi, eax
            //   bd????????           |                     

        $sequence_13 = { 896c2428 e8???????? 8bf0 396c2410 }
            // n = 4, score = 200
            //   896c2428             | mov                 dword ptr [esp + 0x28], ebp
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   396c2410             | cmp                 dword ptr [esp + 0x10], ebp

        $sequence_14 = { 8bf8 8bd7 8d4e08 c1e202 }
            // n = 4, score = 200
            //   8bf8                 | mov                 edi, eax
            //   8bd7                 | mov                 edx, edi
            //   8d4e08               | lea                 ecx, [esi + 8]
            //   c1e202               | shl                 edx, 2

    condition:
        7 of them and filesize < 98304
}