rule win_rm3_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.rm3."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rm3"
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
        $sequence_0 = { 4a f7d2 23fa 3bf8 7609 8b413c }
            // n = 6, score = 2300
            //   4a                   | dec                 eax
            //   f7d2                 | cmp                 dword ptr [edi + 0x20], ebx
            //   23fa                 | je                  0x14a
            //   3bf8                 | dec                 eax
            //   7609                 | mov                 ecx, dword ptr [edi]
            //   8b413c               | xor                 edx, edx

        $sequence_1 = { 48 f7d0 23d0 8b460c 03c2 394508 7303 }
            // n = 7, score = 2300
            //   48                   | mov                 edx, eax
            //   f7d0                 | dec                 esp
            //   23d0                 | mov                 eax, dword ptr [esp + 0x88]
            //   8b460c               | xor                 edx, edx
            //   03c2                 | jae                 0x15
            //   394508               | bt                  dword ptr [esi], 0x1f
            //   7303                 | setb                al

        $sequence_2 = { ff7004 034c240c 8b00 51 }
            // n = 4, score = 2300
            //   ff7004               | mov                 eax, dword ptr [esi + 0xc]
            //   034c240c             | add                 eax, edx
            //   8b00                 | cmp                 dword ptr [ebp + 8], eax
            //   51                   | jae                 0xf

        $sequence_3 = { 8b4138 8b5608 8d5410ff 48 f7d0 23d0 }
            // n = 6, score = 2300
            //   8b4138               | test                eax, eax
            //   8b5608               | dec                 edx
            //   8d5410ff             | not                 edx
            //   48                   | and                 edi, edx
            //   f7d0                 | cmp                 edi, eax
            //   23d0                 | jbe                 0x11

        $sequence_4 = { 8b5e10 8d4438ff 4f f7d7 23c7 8d7c13ff }
            // n = 6, score = 2300
            //   8b5e10               | dec                 eax
            //   8d4438ff             | not                 eax
            //   4f                   | and                 edx, eax
            //   f7d7                 | mov                 eax, dword ptr [esi + 0xc]
            //   23c7                 | add                 eax, edx
            //   8d7c13ff             | cmp                 dword ptr [ebp + 8], eax

        $sequence_5 = { 8b45f8 83c628 ff4dfc 85c0 }
            // n = 4, score = 2300
            //   8b45f8               | dec                 eax
            //   83c628               | sub                 esp, 0x30
            //   ff4dfc               | mov                 edx, 0x104
            //   85c0                 | mov                 ebp, 8

        $sequence_6 = { 55 8bec 51 51 8b483c 03c8 0fb74106 }
            // n = 7, score = 2300
            //   55                   | dec                 eax
            //   8bec                 | cmp                 eax, ebx
            //   51                   | dec                 eax
            //   51                   | mov                 esi, eax
            //   8b483c               | inc                 ecx
            //   03c8                 | mov                 ecx, 0xff
            //   0fb74106             | dec                 eax

        $sequence_7 = { 8d740818 8b4508 3b460c 7247 8b7938 8b4608 8b513c }
            // n = 7, score = 2300
            //   8d740818             | push                ecx
            //   8b4508               | mov                 ecx, dword ptr [eax + 0x3c]
            //   3b460c               | add                 ecx, eax
            //   7247                 | movzx               eax, word ptr [ecx + 6]
            //   8b7938               | dec                 eax
            //   8b4608               | not                 eax
            //   8b513c               | and                 edx, eax

        $sequence_8 = { 83c604 837dfc00 75de 8d85f0feffff 50 ff7508 }
            // n = 6, score = 1800
            //   83c604               | and                 eax, edi
            //   837dfc00             | lea                 edi, [ebx + edx - 1]
            //   75de                 | dec                 edx
            //   8d85f0feffff         | push                ecx
            //   50                   | push                ecx
            //   ff7508               | mov                 ecx, dword ptr [eax + 0x3c]

        $sequence_9 = { 8bc6 e8???????? ff7518 8d856cfeffff ff750c }
            // n = 5, score = 1800
            //   8bc6                 | add                 ecx, eax
            //   e8????????           |                     
            //   ff7518               | movzx               eax, word ptr [ecx + 6]
            //   8d856cfeffff         | and                 dword ptr [ebp - 8], 0
            //   ff750c               | jb                  0x49

        $sequence_10 = { ff750c 8d4d0c 51 8d4d08 51 ff7508 }
            // n = 6, score = 1800
            //   ff750c               | push                eax
            //   8d4d0c               | lea                 esi, [ebp + esi*4 - 0x1a8]
            //   51                   | mov                 dword ptr [ebp + 0x10], eax
            //   8d4d08               | push                esi
            //   51                   | mov                 eax, ebx
            //   ff7508               | pop                 edi

        $sequence_11 = { 50 8db4b558feffff 894510 56 8bc3 }
            // n = 5, score = 1800
            //   50                   | movzx               eax, word ptr [ecx + 6]
            //   8db4b558feffff       | and                 dword ptr [ebp - 8], 0
            //   894510               | push                ebx
            //   56                   | mov                 dword ptr [ebp - 4], eax
            //   8bc3                 | movzx               eax, word ptr [ecx + 0x14]

        $sequence_12 = { e8???????? ff7518 8d85f0feffff ff750c 8d8d6cfeffff 50 e8???????? }
            // n = 7, score = 1800
            //   e8????????           |                     
            //   ff7518               | mov                 edi, dword ptr [ecx + 0x38]
            //   8d85f0feffff         | mov                 eax, dword ptr [esi + 8]
            //   ff750c               | mov                 edx, dword ptr [ecx + 0x3c]
            //   8d8d6cfeffff         | mov                 ebx, dword ptr [esi + 0x10]
            //   50                   | add                 ecx, eax
            //   e8????????           |                     

        $sequence_13 = { e8???????? eb03 6a08 5e 8bc6 5e }
            // n = 6, score = 1800
            //   e8????????           |                     
            //   eb03                 | push                dword ptr [ebp + 0x18]
            //   6a08                 | lea                 eax, [ebp - 0x110]
            //   5e                   | push                dword ptr [ebp + 0xc]
            //   8bc6                 | lea                 ecx, [ebp - 0x194]
            //   5e                   | push                eax

        $sequence_14 = { 53 56 57 8bd8 8bf9 8db5f0feffff 8bce }
            // n = 7, score = 1800
            //   53                   | lea                 eax, [ebp - 0x110]
            //   56                   | push                eax
            //   57                   | push                dword ptr [ebp + 8]
            //   8bd8                 | mov                 eax, esi
            //   8bf9                 | push                dword ptr [ebp + 0x18]
            //   8db5f0feffff         | lea                 eax, [ebp - 0x194]
            //   8bce                 | push                dword ptr [ebp + 0xc]

        $sequence_15 = { 5f 5e 8bc3 2b45f0 }
            // n = 4, score = 1800
            //   5f                   | push                esi
            //   5e                   | jne                 7
            //   8bc3                 | cmp                 dword ptr [ebp - 4], eax
            //   2b45f0               | jne                 0xffffffa4

        $sequence_16 = { e8???????? 85c0 7520 8d5001 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   85c0                 | mov                 esi, ecx
            //   7520                 | cmp                 edx, ebx
            //   8d5001               | mov                 ebp, ebx

        $sequence_17 = { 4c33c0 498bc0 48c1e81b 4c33c0 b825499224 }
            // n = 5, score = 300
            //   4c33c0               | xor                 eax, eax
            //   498bc0               | dec                 eax
            //   48c1e81b             | mov                 ecx, edi
            //   4c33c0               | xor                 edx, edx
            //   b825499224           | inc                 esp

        $sequence_18 = { ff15???????? 33d2 448bc0 488b05???????? b97a040000 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   33d2                 | inc                 ebp
            //   448bc0               | xor                 ecx, ecx
            //   488b05????????       |                     
            //   b97a040000           | inc                 ebp

        $sequence_19 = { 8bfa 488bf1 3bd3 8beb }
            // n = 4, score = 300
            //   8bfa                 | mov                 eax, eax
            //   488bf1               | mov                 ecx, 0x47a
            //   3bd3                 | dec                 esp
            //   8beb                 | xor                 eax, eax

        $sequence_20 = { 8364242800 4c015c2450 488364242000 488d542450 4533c9 4533c0 488bcf }
            // n = 7, score = 300
            //   8364242800           | and                 dword ptr [esp + 0x28], 0
            //   4c015c2450           | dec                 esp
            //   488364242000         | add                 dword ptr [esp + 0x50], ebx
            //   488d542450           | dec                 eax
            //   4533c9               | and                 dword ptr [esp + 0x20], 0
            //   4533c0               | dec                 eax
            //   488bcf               | lea                 edx, [esp + 0x50]

        $sequence_21 = { ff15???????? 8bcf ff15???????? 488b5c2440 488b6c2448 488b742458 4883c430 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   8bcf                 | dec                 esp
            //   ff15????????         |                     
            //   488b5c2440           | xor                 eax, eax
            //   488b6c2448           | mov                 eax, 0x24924925
            //   488b742458           | mov                 edi, edx
            //   4883c430             | dec                 eax

        $sequence_22 = { 4154 4883ec30 ba04010000 bd08000000 }
            // n = 4, score = 300
            //   4154                 | jae                 0x3f
            //   4883ec30             | dec                 eax
            //   ba04010000           | lea                 edx, [esp + 0x38]
            //   bd08000000           | dec                 edx

        $sequence_23 = { 733d 488b0d???????? 488d542438 4a8b0cd9 e8???????? 33d2 }
            // n = 6, score = 300
            //   733d                 | dec                 ecx
            //   488b0d????????       |                     
            //   488d542438           | mov                 eax, eax
            //   4a8b0cd9             | dec                 eax
            //   e8????????           |                     
            //   33d2                 | shr                 eax, 0x1b

        $sequence_24 = { 8811 80fa00 8945f4 894df0 742f 8b45f4 }
            // n = 6, score = 100
            //   8811                 | mov                 eax, ecx
            //   80fa00               | add                 esp, 0x11c
            //   8945f4               | mov                 ecx, dword ptr [eax + 0x3c]
            //   894df0               | mov                 edx, dword ptr [ebp - 0x60]
            //   742f                 | mov                 dword ptr [esp], edx
            //   8b45f4               | mov                 dword ptr [esp + 4], ecx

        $sequence_25 = { 891424 c744240400000000 89742408 8945dc e8???????? 8b45e0 }
            // n = 6, score = 100
            //   891424               | jbe                 0xf
            //   c744240400000000     | and                 dword ptr [ebp - 8], 0
            //   89742408             | push                ebx
            //   8945dc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     
            //   8b45e0               | movzx               eax, word ptr [ecx + 0x14]

        $sequence_26 = { 891424 894c2404 e8???????? b901000000 8985e4feffff 89c8 81c41c010000 }
            // n = 7, score = 100
            //   891424               | mov                 ecx, dword ptr [eax + 8]
            //   894c2404             | and                 eax, edi
            //   e8????????           |                     
            //   b901000000           | lea                 edi, [ebx + edx - 1]
            //   8985e4feffff         | dec                 edx
            //   89c8                 | not                 edx
            //   81c41c010000         | mov                 eax, dword ptr [esi + 8]

        $sequence_27 = { 80e301 0fb6c3 89854cfdffff 8b854cfdffff }
            // n = 4, score = 100
            //   80e301               | mov                 ebx, dword ptr [esi + 0x10]
            //   0fb6c3               | lea                 eax, [eax + edi - 1]
            //   89854cfdffff         | dec                 edi
            //   8b854cfdffff         | not                 edi

        $sequence_28 = { 8b5924 89855cffffff 89d8 c1e81e 83e001 898558ffffff }
            // n = 6, score = 100
            //   8b5924               | push                esi
            //   89855cffffff         | push                edi
            //   89d8                 | mov                 dword ptr [esp], edx
            //   c1e81e               | mov                 dword ptr [esp + 4], ecx
            //   83e001               | mov                 ecx, 1
            //   898558ffffff         | mov                 dword ptr [ebp - 0x11c], eax

        $sequence_29 = { 894c2404 e8???????? 8d0d84308702 31d2 8b75f0 894608 890c24 }
            // n = 7, score = 100
            //   894c2404             | lea                 esi, [eax + ecx + 0x18]
            //   e8????????           |                     
            //   8d0d84308702         | mov                 eax, dword ptr [ebp + 8]
            //   31d2                 | cmp                 eax, dword ptr [esi + 0xc]
            //   8b75f0               | jb                  0x4f
            //   894608               | mov                 edi, dword ptr [ecx + 0x38]
            //   890c24               | mov                 eax, dword ptr [esi + 8]

        $sequence_30 = { 6a00 6a00 68???????? 68???????? 50 8985e4fbffff }
            // n = 6, score = 100
            //   6a00                 | not                 edx
            //   6a00                 | and                 edi, edx
            //   68????????           |                     
            //   68????????           |                     
            //   50                   | cmp                 edi, eax
            //   8985e4fbffff         | jbe                 0xf

        $sequence_31 = { 741a e8???????? 8b4ddc 8945d8 894de8 }
            // n = 5, score = 100
            //   741a                 | mov                 dword ptr [esp + 4], ecx
            //   e8????????           |                     
            //   8b4ddc               | lea                 ecx, [0x2873084]
            //   8945d8               | xor                 edx, edx
            //   894de8               | mov                 esi, dword ptr [ebp - 0x10]

        $sequence_32 = { 894dd8 0f84b8000000 31c0 8b4de8 }
            // n = 4, score = 100
            //   894dd8               | mov                 ecx, dword ptr [ebp - 0x50]
            //   0f84b8000000         | mov                 dword ptr [esp + 8], ecx
            //   31c0                 | mov                 dword ptr [esp + 4], ecx
            //   8b4de8               | mov                 dword ptr [ebp - 0x20], eax

        $sequence_33 = { 8bb550fdffff 8974240c 898548fdffff 898d44fdffff 899540fdffff e8???????? 8b8d50fdffff }
            // n = 7, score = 100
            //   8bb550fdffff         | and                 eax, edi
            //   8974240c             | lea                 edi, [ebx + edx - 1]
            //   898548fdffff         | mov                 esi, dword ptr [eax]
            //   898d44fdffff         | mov                 dword ptr [ecx], esi
            //   899540fdffff         | mov                 esi, dword ptr [eax + 4]
            //   e8????????           |                     
            //   8b8d50fdffff         | mov                 dword ptr [ecx + 4], esi

        $sequence_34 = { 898550fdffff 898d4cfdffff 0f849b000000 b80d000000 b901000000 }
            // n = 5, score = 100
            //   898550fdffff         | mov                 dword ptr [esi + 8], eax
            //   898d4cfdffff         | mov                 dword ptr [esp], ecx
            //   0f849b000000         | mov                 edx, dword ptr [ebp - 0x41c]
            //   b80d000000           | push                edx
            //   b901000000           | mov                 dword ptr [ebp - 0x444], eax

        $sequence_35 = { 8b483c 8b55a0 891424 894c2404 8b4db0 894c2408 e8???????? }
            // n = 7, score = 100
            //   8b483c               | mov                 edx, dword ptr [ecx + 0x3c]
            //   8b55a0               | mov                 ebx, dword ptr [esi + 0x10]
            //   891424               | lea                 eax, [eax + edi - 1]
            //   894c2404             | dec                 edi
            //   8b4db0               | not                 edi
            //   894c2408             | push                edi
            //   e8????????           |                     

        $sequence_36 = { 894c2404 8945e0 e8???????? 31c0 }
            // n = 4, score = 100
            //   894c2404             | lea                 esi, [eax + ecx + 0x18]
            //   8945e0               | mov                 eax, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   31c0                 | cmp                 eax, dword ptr [esi + 0xc]

        $sequence_37 = { 8b0d???????? 8b95e4fbffff 52 8985bcfbffff ffd1 8b0d???????? 8b95e8fbffff }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   8b95e4fbffff         | mov                 edx, dword ptr [ecx + 0x3c]
            //   52                   | push                dword ptr [eax + 4]
            //   8985bcfbffff         | add                 ecx, dword ptr [esp + 0xc]
            //   ffd1                 | mov                 eax, dword ptr [eax]
            //   8b0d????????         |                     
            //   8b95e8fbffff         | push                ecx

        $sequence_38 = { 0fb77214 01f1 8945dc 894dd8 eb23 }
            // n = 5, score = 100
            //   0fb77214             | jb                  0x53
            //   01f1                 | dec                 edx
            //   8945dc               | not                 edx
            //   894dd8               | and                 edi, edx
            //   eb23                 | cmp                 edi, eax

        $sequence_39 = { b901000000 83f800 8b8564ffffff 0f44c8 8b8560ffffff 83c001 }
            // n = 6, score = 100
            //   b901000000           | mov                 ecx, dword ptr [eax + 8]
            //   83f800               | push                dword ptr [eax + 4]
            //   8b8564ffffff         | push                0
            //   0f44c8               | push                0
            //   8b8560ffffff         | push                eax
            //   83c001               | mov                 dword ptr [ebp - 0x41c], eax

    condition:
        7 of them and filesize < 221184
}