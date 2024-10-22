rule win_ghostemperor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ghostemperor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghostemperor"
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
        $sequence_0 = { 4839d0 0f86ea000000 4989c9 4889d0 458d5aff }
            // n = 5, score = 200
            //   4839d0               | add                 ecx, edx
            //   0f86ea000000         | mov                 edx, ecx
            //   4989c9               | shl                 edx, 5
            //   4889d0               | mov                 ebx, ecx
            //   458d5aff             | sub                 ebx, edx

        $sequence_1 = { 4c89f1 ff15???????? 89f0 4883c420 5b }
            // n = 5, score = 200
            //   4c89f1               | shl                 edx, 5
            //   ff15????????         |                     
            //   89f0                 | mov                 ebx, ecx
            //   4883c420             | sub                 ebx, edx
            //   5b                   | add                 ebx, ecx

        $sequence_2 = { 660f1f440000 488b3cf0 49313cf1 488b7cf008 49317cf108 488b7cf010 }
            // n = 6, score = 200
            //   660f1f440000         | mov                 edx, ecx
            //   488b3cf0             | shl                 edx, 5
            //   49313cf1             | mov                 ebx, ecx
            //   488b7cf008           | sub                 ebx, edx
            //   49317cf108           | add                 ecx, edx
            //   488b7cf010           | mov                 edx, ecx

        $sequence_3 = { 7453 8a08 413009 4183f801 7448 8a4801 }
            // n = 6, score = 200
            //   7453                 | add                 esp, 0x20
            //   8a08                 | add                 ecx, edx
            //   413009               | mov                 edx, ecx
            //   4183f801             | shl                 edx, 5
            //   7448                 | mov                 ebx, ecx
            //   8a4801               | add                 ecx, edx

        $sequence_4 = { 4889c1 31d2 4989f0 ff15???????? 83f8ff }
            // n = 5, score = 200
            //   4889c1               | sub                 esp, 0x20
            //   31d2                 | inc                 ecx
            //   4989f0               | call                esi
            //   ff15????????         |                     
            //   83f8ff               | dec                 eax

        $sequence_5 = { 41c60300 4d3bd3 75f0 4c8b1424 4c8b5c2408 4883c410 c3 }
            // n = 7, score = 200
            //   41c60300             | dec                 eax
            //   4d3bd3               | mov                 dword ptr [esp + 0x48], edi
            //   75f0                 | inc                 esp
            //   4c8b1424             | mov                 eax, ebp
            //   4c8b5c2408           | mov                 dword ptr [esp + 0x40], eax
            //   4883c410             | dec                 ecx
            //   c3                   | mov                 edx, esi

        $sequence_6 = { 31d2 41b801000000 4531c9 ff15???????? }
            // n = 4, score = 200
            //   31d2                 | dec                 eax
            //   41b801000000         | add                 esp, 0x10
            //   4531c9               | ret                 
            //   ff15????????         |                     

        $sequence_7 = { 31f6 31d2 660f1f440000 488b3cf0 }
            // n = 4, score = 200
            //   31f6                 | add                 ebx, eax
            //   31d2                 | imul                ecx, ebx, 0x3e8
            //   660f1f440000         | add                 ecx, 0x7530
            //   488b3cf0             | dec                 eax

        $sequence_8 = { b801000000 4883c428 5b 5d 5f 5e }
            // n = 6, score = 200
            //   b801000000           | add                 esp, 0x10
            //   4883c428             | ret                 
            //   5b                   | dec                 esp
            //   5d                   | mov                 edx, dword ptr [esp]
            //   5f                   | dec                 esp
            //   5e                   | mov                 ebx, dword ptr [esp + 8]

        $sequence_9 = { 4883c410 c3 ff25???????? ff25???????? ff25???????? ff25???????? ff25???????? }
            // n = 7, score = 200
            //   4883c410             | inc                 esp
            //   c3                   | mov                 dword ptr [esp + 0x50], edi
            //   ff25????????         |                     
            //   ff25????????         |                     
            //   ff25????????         |                     
            //   ff25????????         |                     
            //   ff25????????         |                     

        $sequence_10 = { 01d1 89ca c1e205 89cb }
            // n = 4, score = 100
            //   01d1                 | mov                 eax, dword ptr [ebp + 0x268]
            //   89ca                 | mov                 byte ptr [eax + ecx + 0xc], dl
            //   c1e205               | dec                 eax
            //   89cb                 | mov                 eax, dword ptr [ebp + 0x2b0]

        $sequence_11 = { 01c3 69cbe8030000 81c130750000 4883ec20 }
            // n = 4, score = 100
            //   01c3                 | add                 esp, 0x10
            //   69cbe8030000         | dec                 esp
            //   81c130750000         | mov                 ebx, dword ptr [esp + 8]
            //   4883ec20             | dec                 eax

        $sequence_12 = { d3f8 660bf8 664103f8 664123ff 6642337c45f0 6642897c450a }
            // n = 6, score = 100
            //   d3f8                 | inc                 edi
            //   660bf8               | cmp                 edi, 8
            //   664103f8             | sar                 eax, cl
            //   664123ff             | or                  di, ax
            //   6642337c45f0         | inc                 cx
            //   6642897c450a         | add                 edi, eax

        $sequence_13 = { 488b4c2460 8b4530 2514010000 4c8b7140 094134 33ff }
            // n = 6, score = 100
            //   488b4c2460           | inc                 cx
            //   8b4530               | and                 edi, edi
            //   2514010000           | inc                 dx
            //   4c8b7140             | xor                 edi, dword ptr [ebp + eax*2 - 0x10]
            //   094134               | inc                 dx
            //   33ff                 | mov                 dword ptr [ebp + eax*2 + 0xa], edi

        $sequence_14 = { 33c9 ff15???????? ffc7 83ff08 }
            // n = 4, score = 100
            //   33c9                 | mov                 esi, edi
            //   ff15????????         |                     
            //   ffc7                 | test                al, al
            //   83ff08               | xor                 ecx, ecx

        $sequence_15 = { 00c2 488b8568020000 8854080c 488b85b0020000 }
            // n = 4, score = 100
            //   00c2                 | dec                 esp
            //   488b8568020000       | mov                 edx, dword ptr [esp]
            //   8854080c             | dec                 esp
            //   488b85b0020000       | mov                 ebx, dword ptr [esp + 8]

        $sequence_16 = { 0f428558010000 4533f6 898558010000 85c0 }
            // n = 4, score = 100
            //   0f428558010000       | dec                 eax
            //   4533f6               | mov                 ecx, dword ptr [esp + 0x60]
            //   898558010000         | mov                 eax, dword ptr [ebp + 0x30]
            //   85c0                 | and                 eax, 0x114

        $sequence_17 = { 01c1 89ca c1ea1f c1f904 }
            // n = 4, score = 100
            //   01c1                 | dec                 ebp
            //   89ca                 | cmp                 edx, ebx
            //   c1ea1f               | jne                 0xfffffff2
            //   c1f904               | dec                 esp

        $sequence_18 = { 498bcf 894540 4d8bf7 ff15???????? 84c0 }
            // n = 5, score = 100
            //   498bcf               | dec                 ecx
            //   894540               | mov                 ecx, edi
            //   4d8bf7               | mov                 dword ptr [ebp + 0x40], eax
            //   ff15????????         |                     
            //   84c0                 | dec                 ebp

        $sequence_19 = { 41895909 41c6410dc3 0f22c1 498bf1 4c8b4590 }
            // n = 5, score = 100
            //   41895909             | dec                 esp
            //   41c6410dc3           | mov                 esi, dword ptr [ecx + 0x40]
            //   0f22c1               | or                  dword ptr [ecx + 0x34], eax
            //   498bf1               | xor                 edi, edi
            //   4c8b4590             | cmovb               eax, dword ptr [ebp + 0x158]

        $sequence_20 = { 448bce 48897c2448 448bc5 89442440 498bd6 }
            // n = 5, score = 100
            //   448bce               | mov                 dword ptr [ecx + 9], ebx
            //   48897c2448           | inc                 ecx
            //   448bc5               | mov                 byte ptr [ecx + 0xd], 0xc3
            //   89442440             | mov                 cr0, ecx
            //   498bd6               | dec                 ecx

        $sequence_21 = { f30f7f452f ff5050 44897c2450 418d4602 4c897c2448 }
            // n = 5, score = 100
            //   f30f7f452f           | inc                 ebp
            //   ff5050               | xor                 esi, esi
            //   44897c2450           | mov                 dword ptr [ebp + 0x158], eax
            //   418d4602             | test                eax, eax
            //   4c897c2448           | inc                 ecx

    condition:
        7 of them and filesize < 1115136
}