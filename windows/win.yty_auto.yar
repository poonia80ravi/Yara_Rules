rule win_yty_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.yty."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yty"
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
        $sequence_0 = { 50 8d45f4 64a300000000 8b7508 33ff 897dd8 }
            // n = 6, score = 500
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33ff                 | xor                 edi, edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi

        $sequence_1 = { 83e001 0f840c000000 8365d8fe 8b7508 e9???????? c3 8b542408 }
            // n = 7, score = 500
            //   83e001               | and                 eax, 1
            //   0f840c000000         | je                  0x12
            //   8365d8fe             | and                 dword ptr [ebp - 0x28], 0xfffffffe
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   e9????????           |                     
            //   c3                   | ret                 
            //   8b542408             | mov                 edx, dword ptr [esp + 8]

        $sequence_2 = { 33db 895de8 885def 8975e0 }
            // n = 4, score = 400
            //   33db                 | xor                 ebx, ebx
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   885def               | mov                 byte ptr [ebp - 0x11], bl
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi

        $sequence_3 = { c746140f000000 c7461000000000 50 8bce c60600 e8???????? 8b5610 }
            // n = 7, score = 400
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   c60600               | mov                 byte ptr [esi], 0
            //   e8????????           |                     
            //   8b5610               | mov                 edx, dword ptr [esi + 0x10]

        $sequence_4 = { 57 50 8d45f4 64a300000000 8d8524ffffff 50 e8???????? }
            // n = 7, score = 400
            //   57                   | push                edi
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8d8524ffffff         | lea                 eax, [ebp - 0xdc]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 6a01 8bcf e8???????? 8b0e 8b5104 8b443238 }
            // n = 6, score = 400
            //   6a01                 | push                1
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   8b443238             | mov                 eax, dword ptr [edx + esi + 0x38]

        $sequence_6 = { 53 50 e8???????? 83c40c 8d8de8fdffff 51 }
            // n = 6, score = 400
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   51                   | push                ecx

        $sequence_7 = { 56 6a64 68???????? e8???????? }
            // n = 4, score = 400
            //   56                   | push                esi
            //   6a64                 | push                0x64
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_8 = { c645fc01 e8???????? 8b10 8b4a04 03c8 }
            // n = 5, score = 400
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]
            //   03c8                 | add                 ecx, eax

        $sequence_9 = { e9???????? 8b5508 397d1c 7303 }
            // n = 4, score = 400
            //   e9????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   397d1c               | cmp                 dword ptr [ebp + 0x1c], edi
            //   7303                 | jae                 5

        $sequence_10 = { 8b5610 33c9 33c0 8d7910 85d2 }
            // n = 5, score = 400
            //   8b5610               | mov                 edx, dword ptr [esi + 0x10]
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   8d7910               | lea                 edi, [ecx + 0x10]
            //   85d2                 | test                edx, edx

        $sequence_11 = { bf10000000 40 3b4610 0f82dbfeffff 397d1c 720c 8b4508 }
            // n = 7, score = 400
            //   bf10000000           | mov                 edi, 0x10
            //   40                   | inc                 eax
            //   3b4610               | cmp                 eax, dword ptr [esi + 0x10]
            //   0f82dbfeffff         | jb                  0xfffffee1
            //   397d1c               | cmp                 dword ptr [ebp + 0x1c], edi
            //   720c                 | jb                  0xe
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_12 = { ff15???????? 8a857bffffff 8b4df4 64890d00000000 59 }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   8a857bffffff         | mov                 al, byte ptr [ebp - 0x85]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx

        $sequence_13 = { 8d8de8fdffff 51 53 53 6a28 53 ff15???????? }
            // n = 7, score = 400
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6a28                 | push                0x28
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_14 = { 807def00 8b5de8 7503 83cb02 8b16 }
            // n = 5, score = 400
            //   807def00             | cmp                 byte ptr [ebp - 0x11], 0
            //   8b5de8               | mov                 ebx, dword ptr [ebp - 0x18]
            //   7503                 | jne                 5
            //   83cb02               | or                  ebx, 2
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_15 = { 397d1c 7303 8d5508 8b4e10 397e14 }
            // n = 5, score = 400
            //   397d1c               | cmp                 dword ptr [ebp + 0x1c], edi
            //   7303                 | jae                 5
            //   8d5508               | lea                 edx, [ebp + 8]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   397e14               | cmp                 dword ptr [esi + 0x14], edi

        $sequence_16 = { 668910 8bc6 5b 8be5 5d c20400 }
            // n = 6, score = 400
            //   668910               | mov                 word ptr [eax], dx
            //   8bc6                 | mov                 eax, esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4

        $sequence_17 = { 8bfe 8a1402 2ad1 80ea13 }
            // n = 4, score = 400
            //   8bfe                 | mov                 edi, esi
            //   8a1402               | mov                 dl, byte ptr [edx + eax]
            //   2ad1                 | sub                 dl, cl
            //   80ea13               | sub                 dl, 0x13

        $sequence_18 = { 894608 8945fc 56 c745f001000000 e8???????? 83c404 }
            // n = 6, score = 400
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_19 = { 7214 8a1402 8b3e 2ad1 80ea13 b902000000 e9???????? }
            // n = 7, score = 400
            //   7214                 | jb                  0x16
            //   8a1402               | mov                 dl, byte ptr [edx + eax]
            //   8b3e                 | mov                 edi, dword ptr [esi]
            //   2ad1                 | sub                 dl, cl
            //   80ea13               | sub                 dl, 0x13
            //   b902000000           | mov                 ecx, 2
            //   e9????????           |                     

        $sequence_20 = { ffd2 8b8568ffffff 8b08 8b5108 }
            // n = 4, score = 400
            //   ffd2                 | call                edx
            //   8b8568ffffff         | mov                 eax, dword ptr [ebp - 0x98]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]

        $sequence_21 = { 7204 8b07 eb02 8bc7 8b4de0 }
            // n = 5, score = 300
            //   7204                 | jb                  6
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   eb02                 | jmp                 4
            //   8bc7                 | mov                 eax, edi
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]

        $sequence_22 = { 8ad1 c0ea02 8ac4 80e20f }
            // n = 4, score = 300
            //   8ad1                 | mov                 dl, cl
            //   c0ea02               | shr                 dl, 2
            //   8ac4                 | mov                 al, ah
            //   80e20f               | and                 dl, 0xf

        $sequence_23 = { 6a6d 56 ff15???????? 8b3d???????? 6a00 6a00 6a00 }
            // n = 7, score = 300
            //   6a6d                 | push                0x6d
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_24 = { 8b4c1938 895dd4 85c9 7405 8b01 ff5004 c745fc00000000 }
            // n = 7, score = 200
            //   8b4c1938             | mov                 ecx, dword ptr [ecx + ebx + 0x38]
            //   895dd4               | mov                 dword ptr [ebp - 0x2c], ebx
            //   85c9                 | test                ecx, ecx
            //   7405                 | je                  7
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5004               | call                dword ptr [eax + 4]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_25 = { e8???????? ebd7 85ff 75d7 897e10 83f810 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   ebd7                 | jmp                 0xffffffd9
            //   85ff                 | test                edi, edi
            //   75d7                 | jne                 0xffffffd9
            //   897e10               | mov                 dword ptr [esi + 0x10], edi
            //   83f810               | cmp                 eax, 0x10

        $sequence_26 = { 8b4d08 83e13f 6bd130 8b048500b04600 0fb64c1028 83e102 }
            // n = 6, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   83e13f               | and                 ecx, 0x3f
            //   6bd130               | imul                edx, ecx, 0x30
            //   8b048500b04600       | mov                 eax, dword ptr [eax*4 + 0x46b000]
            //   0fb64c1028           | movzx               ecx, byte ptr [eax + edx + 0x28]
            //   83e102               | and                 ecx, 2

        $sequence_27 = { c7463454ee4200 57 ff7634 c6463c01 e8???????? eb14 }
            // n = 6, score = 100
            //   c7463454ee4200       | mov                 dword ptr [esi + 0x34], 0x42ee54
            //   57                   | push                edi
            //   ff7634               | push                dword ptr [esi + 0x34]
            //   c6463c01             | mov                 byte ptr [esi + 0x3c], 1
            //   e8????????           |                     
            //   eb14                 | jmp                 0x16

        $sequence_28 = { 7cf1 eb07 8b0cc5a4034300 894de4 85c9 7455 8b4510 }
            // n = 7, score = 100
            //   7cf1                 | jl                  0xfffffff3
            //   eb07                 | jmp                 9
            //   8b0cc5a4034300       | mov                 ecx, dword ptr [eax*8 + 0x4303a4]
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   85c9                 | test                ecx, ecx
            //   7455                 | je                  0x57
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_29 = { c1f806 8b4df4 83e13f 6bd130 03148500b04600 }
            // n = 5, score = 100
            //   c1f806               | sar                 eax, 6
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   83e13f               | and                 ecx, 0x3f
            //   6bd130               | imul                edx, ecx, 0x30
            //   03148500b04600       | add                 edx, dword ptr [eax*4 + 0x46b000]

        $sequence_30 = { 8b4508 0345e0 894508 8b4508 }
            // n = 4, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0345e0               | add                 eax, dword ptr [ebp - 0x20]
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_31 = { c745c800000000 c745ccf0064100 a1???????? 8d4dc8 33c1 8945d0 8b5518 }
            // n = 7, score = 100
            //   c745c800000000       | mov                 dword ptr [ebp - 0x38], 0
            //   c745ccf0064100       | mov                 dword ptr [ebp - 0x34], 0x4106f0
            //   a1????????           |                     
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   33c1                 | xor                 eax, ecx
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]

        $sequence_32 = { 837dec00 7c08 8b45ec 3b45e0 }
            // n = 4, score = 100
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0
            //   7c08                 | jl                  0xa
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   3b45e0               | cmp                 eax, dword ptr [ebp - 0x20]

        $sequence_33 = { e9???????? 8b45d0 c60000 e9???????? }
            // n = 4, score = 100
            //   e9????????           |                     
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   c60000               | mov                 byte ptr [eax], 0
            //   e9????????           |                     

        $sequence_34 = { 50 8b4d08 51 e8???????? 8945f8 837df800 7c27 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7c27                 | jl                  0x29

        $sequence_35 = { 740e 6aff 6a00 68???????? e8???????? be???????? }
            // n = 6, score = 100
            //   740e                 | je                  0x10
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   be????????           |                     

        $sequence_36 = { 8bd0 e8???????? 83c404 8d8d4cfbffff 8bd0 e8???????? 83c404 }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d8d4cfbffff         | lea                 ecx, [ebp - 0x4b4]
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_37 = { 8945dc 0fb64dff 85c9 7409 c745e4c4ea4500 eb07 c745e490ea4500 }
            // n = 7, score = 100
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   0fb64dff             | movzx               ecx, byte ptr [ebp - 1]
            //   85c9                 | test                ecx, ecx
            //   7409                 | je                  0xb
            //   c745e4c4ea4500       | mov                 dword ptr [ebp - 0x1c], 0x45eac4
            //   eb07                 | jmp                 9
            //   c745e490ea4500       | mov                 dword ptr [ebp - 0x1c], 0x45ea90

        $sequence_38 = { c645fc04 8b85a4bcf0ff 83f810 7245 8b8d90bcf0ff 40 3d00100000 }
            // n = 7, score = 100
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8b85a4bcf0ff         | mov                 eax, dword ptr [ebp - 0xf435c]
            //   83f810               | cmp                 eax, 0x10
            //   7245                 | jb                  0x47
            //   8b8d90bcf0ff         | mov                 ecx, dword ptr [ebp - 0xf4370]
            //   40                   | inc                 eax
            //   3d00100000           | cmp                 eax, 0x1000

        $sequence_39 = { c7442408???????? c744240464000000 8d458b 890424 e8???????? 8d458b 89442404 }
            // n = 7, score = 100
            //   c7442408????????     |                     
            //   c744240464000000     | mov                 dword ptr [esp + 4], 0x64
            //   8d458b               | lea                 eax, [ebp - 0x75]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8d458b               | lea                 eax, [ebp - 0x75]
            //   89442404             | mov                 dword ptr [esp + 4], eax

        $sequence_40 = { eb09 8b4df8 83c101 894df8 8b55f8 833c95a0cf440000 7411 }
            // n = 7, score = 100
            //   eb09                 | jmp                 0xb
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c101               | add                 ecx, 1
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   833c95a0cf440000     | cmp                 dword ptr [edx*4 + 0x44cfa0], 0
            //   7411                 | je                  0x13

        $sequence_41 = { c7443098dc724300 8b4698 8b4804 8d41f8 89443194 c745fc00000000 }
            // n = 6, score = 100
            //   c7443098dc724300     | mov                 dword ptr [eax + esi - 0x68], 0x4372dc
            //   8b4698               | mov                 eax, dword ptr [esi - 0x68]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8d41f8               | lea                 eax, [ecx - 8]
            //   89443194             | mov                 dword ptr [ecx + esi - 0x6c], eax
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_42 = { 66a3???????? e8???????? 83c404 8b4df4 }
            // n = 4, score = 100
            //   66a3????????         |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_43 = { eb2e 0c80 88441628 8b04bd60cb4300 c644102902 eb1a 247f }
            // n = 7, score = 100
            //   eb2e                 | jmp                 0x30
            //   0c80                 | or                  al, 0x80
            //   88441628             | mov                 byte ptr [esi + edx + 0x28], al
            //   8b04bd60cb4300       | mov                 eax, dword ptr [edi*4 + 0x43cb60]
            //   c644102902           | mov                 byte ptr [eax + edx + 0x29], 2
            //   eb1a                 | jmp                 0x1c
            //   247f                 | and                 al, 0x7f

        $sequence_44 = { 6a00 e8???????? 8945ec 5f 5e 5b 81c4d8000000 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c4d8000000         | add                 esp, 0xd8

        $sequence_45 = { bfcccccccc 3bf3 743f 895dfc }
            // n = 4, score = 100
            //   bfcccccccc           | mov                 edi, 0xcccccccc
            //   3bf3                 | cmp                 esi, ebx
            //   743f                 | je                  0x41
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx

        $sequence_46 = { 01d0 0505010000 8945f4 eb20 8b45f4 05???????? }
            // n = 6, score = 100
            //   01d0                 | add                 eax, edx
            //   0505010000           | add                 eax, 0x105
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   eb20                 | jmp                 0x22
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   05????????           |                     

        $sequence_47 = { 89442404 c70424???????? e8???????? eb0c c70424???????? }
            // n = 5, score = 100
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c70424????????       |                     
            //   e8????????           |                     
            //   eb0c                 | jmp                 0xe
            //   c70424????????       |                     

        $sequence_48 = { c7042488130000 e8???????? 83ec04 c7442404???????? c70424???????? e8???????? }
            // n = 6, score = 100
            //   c7042488130000       | mov                 dword ptr [esp], 0x1388
            //   e8????????           |                     
            //   83ec04               | sub                 esp, 4
            //   c7442404????????     |                     
            //   c70424????????       |                     
            //   e8????????           |                     

        $sequence_49 = { 0f87c8090000 ff2485f6fe4100 33c0 838de8fdffffff 898594fdffff 8985a4fdffff }
            // n = 6, score = 100
            //   0f87c8090000         | ja                  0x9ce
            //   ff2485f6fe4100       | jmp                 dword ptr [eax*4 + 0x41fef6]
            //   33c0                 | xor                 eax, eax
            //   838de8fdffffff       | or                  dword ptr [ebp - 0x218], 0xffffffff
            //   898594fdffff         | mov                 dword ptr [ebp - 0x26c], eax
            //   8985a4fdffff         | mov                 dword ptr [ebp - 0x25c], eax

        $sequence_50 = { 39b880f94200 0f8491000000 ff45e4 83c030 }
            // n = 4, score = 100
            //   39b880f94200         | cmp                 dword ptr [eax + 0x42f980], edi
            //   0f8491000000         | je                  0x97
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   83c030               | add                 eax, 0x30

        $sequence_51 = { e8???????? ebd1 8bc8 c1f905 8d3c8da0244300 8bf0 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   ebd1                 | jmp                 0xffffffd3
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8d3c8da0244300       | lea                 edi, [ecx*4 + 0x4324a0]
            //   8bf0                 | mov                 esi, eax

        $sequence_52 = { 89e5 83ec28 c745f000000000 c745f400000000 eb2a 8b45f4 8b048520304000 }
            // n = 7, score = 100
            //   89e5                 | mov                 ebp, esp
            //   83ec28               | sub                 esp, 0x28
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   eb2a                 | jmp                 0x2c
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b048520304000       | mov                 eax, dword ptr [eax*4 + 0x403020]

        $sequence_53 = { 5b 5f 5d c3 8d4c2404 83e4f0 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   83e4f0               | and                 esp, 0xfffffff0

        $sequence_54 = { 890424 e8???????? c78588feffff62625678 c7858cfeffff6f747a62 }
            // n = 4, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   c78588feffff62625678     | mov    dword ptr [ebp - 0x178], 0x78566262
            //   c7858cfeffff6f747a62     | mov    dword ptr [ebp - 0x174], 0x627a746f

    condition:
        7 of them and filesize < 1097728
}