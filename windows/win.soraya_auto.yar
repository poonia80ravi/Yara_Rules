rule win_soraya_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.soraya."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soraya"
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
        $sequence_0 = { ff15???????? 8d48bf 80f919 77f2 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8d48bf               | lea                 ecx, [eax - 0x41]
            //   80f919               | cmp                 cl, 0x19
            //   77f2                 | ja                  0xfffffff4

        $sequence_1 = { 33c9 ff15???????? c744244401000000 8bfb 4c8bf8 8b4c2440 3bf9 }
            // n = 7, score = 100
            //   33c9                 | mov                 eax, dword ptr [edx + 4]
            //   ff15????????         |                     
            //   c744244401000000     | dec                 esp
            //   8bfb                 | lea                 eax, [edx + 8]
            //   4c8bf8               | dec                 eax
            //   8b4c2440             | sub                 eax, 8
            //   3bf9                 | add                 ebx, eax

        $sequence_2 = { 55 8bec 83ec18 8365f000 53 56 57 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec18               | sub                 esp, 0x18
            //   8365f000             | and                 dword ptr [ebp - 0x10], 0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_3 = { 85f6 740a 56 e8???????? 59 }
            // n = 5, score = 100
            //   85f6                 | test                esi, esi
            //   740a                 | je                  0xc
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_4 = { 4533c0 33d2 448bfb 8958a8 }
            // n = 4, score = 100
            //   4533c0               | cmp                 ebx, 0xc
            //   33d2                 | jb                  0xffffffed
            //   448bfb               | inc                 esp
            //   8958a8               | mov                 eax, ebx

        $sequence_5 = { 052d0f0000 355b5e0000 8945e8 66a1???????? 0fb7c8 b8994a0000 99 }
            // n = 7, score = 100
            //   052d0f0000           | add                 eax, 0xf2d
            //   355b5e0000           | xor                 eax, 0x5e5b
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   66a1????????         |                     
            //   0fb7c8               | movzx               ecx, ax
            //   b8994a0000           | mov                 eax, 0x4a99
            //   99                   | cdq                 

        $sequence_6 = { 57 ff75e8 8d4588 50 e8???????? 8b45fc }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   8d4588               | lea                 eax, [ebp - 0x78]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { 668945ac 83c0f3 668945ae b8bc610000 668945b0 }
            // n = 5, score = 100
            //   668945ac             | mov                 word ptr [ebp - 0x54], ax
            //   83c0f3               | add                 eax, -0xd
            //   668945ae             | mov                 word ptr [ebp - 0x52], ax
            //   b8bc610000           | mov                 eax, 0x61bc
            //   668945b0             | mov                 word ptr [ebp - 0x50], ax

        $sequence_8 = { 8d45d8 50 ff15???????? 85c0 7556 3975f4 7472 }
            // n = 7, score = 100
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7556                 | jne                 0x58
            //   3975f4               | cmp                 dword ptr [ebp - 0xc], esi
            //   7472                 | je                  0x74

        $sequence_9 = { 0f84a6000000 8b442410 8b4c2410 33c6 33ce }
            // n = 5, score = 100
            //   0f84a6000000         | je                  0xac
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   33c6                 | xor                 eax, esi
            //   33ce                 | xor                 ecx, esi

        $sequence_10 = { 4533c0 418d5064 ff15???????? 4883c430 5b c3 4053 }
            // n = 7, score = 100
            //   4533c0               | xor                 ecx, ecx
            //   418d5064             | mov                 dword ptr [esp + 0x44], 1
            //   ff15????????         |                     
            //   4883c430             | mov                 edi, ebx
            //   5b                   | dec                 esp
            //   c3                   | mov                 edi, eax
            //   4053                 | mov                 ecx, dword ptr [esp + 0x40]

        $sequence_11 = { 85c9 7e27 8b55fc 8b4a0c 3bc1 }
            // n = 5, score = 100
            //   85c9                 | test                ecx, ecx
            //   7e27                 | jle                 0x29
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4a0c               | mov                 ecx, dword ptr [edx + 0xc]
            //   3bc1                 | cmp                 eax, ecx

        $sequence_12 = { ff15???????? e8???????? 488d4dd0 488bd0 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   e8????????           |                     
            //   488d4dd0             | dec                 eax
            //   488bd0               | lea                 ecx, [ebp - 0x30]

        $sequence_13 = { 7468 41bb00f00000 448bd0 8b4204 4c8d4208 4883e808 }
            // n = 6, score = 100
            //   7468                 | lea                 ecx, [0xffffdd5b]
            //   41bb00f00000         | dec                 eax
            //   448bd0               | add                 edx, 0x140
            //   8b4204               | inc                 ebp
            //   4c8d4208             | xor                 ecx, ecx
            //   4883e808             | je                  0x6a

        $sequence_14 = { 7703 8955f4 33d2 8955d0 }
            // n = 4, score = 100
            //   7703                 | ja                  5
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   33d2                 | xor                 edx, edx
            //   8955d0               | mov                 dword ptr [ebp - 0x30], edx

        $sequence_15 = { 53 c744240c71f90500 56 57 bb70f90500 895c2410 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   c744240c71f90500     | mov                 dword ptr [esp + 0xc], 0x5f971
            //   56                   | push                esi
            //   57                   | push                edi
            //   bb70f90500           | mov                 ebx, 0x5f970
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx

        $sequence_16 = { 3b11 7322 8b4d20 034d24 894d20 8b4904 }
            // n = 6, score = 100
            //   3b11                 | cmp                 edx, dword ptr [ecx]
            //   7322                 | jae                 0x24
            //   8b4d20               | mov                 ecx, dword ptr [ebp + 0x20]
            //   034d24               | add                 ecx, dword ptr [ebp + 0x24]
            //   894d20               | mov                 dword ptr [ebp + 0x20], ecx
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]

        $sequence_17 = { 5e 741e 8d140e 803a68 750d 395c0e01 7507 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   741e                 | je                  0x20
            //   8d140e               | lea                 edx, [esi + ecx]
            //   803a68               | cmp                 byte ptr [edx], 0x68
            //   750d                 | jne                 0xf
            //   395c0e01             | cmp                 dword ptr [esi + ecx + 1], ebx
            //   7507                 | jne                 9

        $sequence_18 = { 03d8 83fb0c 72e8 448bc3 }
            // n = 4, score = 100
            //   03d8                 | inc                 ecx
            //   83fb0c               | mov                 ebx, 0xf000
            //   72e8                 | inc                 esp
            //   448bc3               | mov                 edx, eax

        $sequence_19 = { 50 b8???????? ffd0 8d0437 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   b8????????           |                     
            //   ffd0                 | call                eax
            //   8d0437               | lea                 eax, [edi + esi]

        $sequence_20 = { ff15???????? eb25 488b15???????? 8364242000 488d0d5bddffff 4881c240010000 4533c9 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   eb25                 | dec                 eax
            //   488b15????????       |                     
            //   8364242000           | mov                 edx, eax
            //   488d0d5bddffff       | jmp                 0x27
            //   4881c240010000       | and                 dword ptr [esp + 0x20], 0
            //   4533c9               | dec                 eax

        $sequence_21 = { 33fb 8b5d14 33d0 03d1 }
            // n = 4, score = 100
            //   33fb                 | xor                 edi, ebx
            //   8b5d14               | mov                 ebx, dword ptr [ebp + 0x14]
            //   33d0                 | xor                 edx, eax
            //   03d1                 | add                 edx, ecx

        $sequence_22 = { 8bec 57 ff7530 ff752c ff7528 ff7524 ff7520 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   57                   | push                edi
            //   ff7530               | push                dword ptr [ebp + 0x30]
            //   ff752c               | push                dword ptr [ebp + 0x2c]
            //   ff7528               | push                dword ptr [ebp + 0x28]
            //   ff7524               | push                dword ptr [ebp + 0x24]
            //   ff7520               | push                dword ptr [ebp + 0x20]

    condition:
        7 of them and filesize < 188416
}