rule win_winnti_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.winnti."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winnti"
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
        $sequence_0 = { 50 ffd6 8b0d???????? 6a00 8b5110 52 ff15???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_1 = { 50 8d8424cc000000 52 50 e8???????? }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8d8424cc000000       | lea                 eax, [esp + 0xcc]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 8b75dc 8bfc fc f3a5 ff550c }
            // n = 5, score = 200
            //   8b75dc               | mov                 esi, dword ptr [ebp - 0x24]
            //   8bfc                 | mov                 edi, esp
            //   fc                   | cld                 
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff550c               | call                dword ptr [ebp + 0xc]

        $sequence_3 = { e8???????? 83c8ff 5e c20400 33c0 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c8ff               | or                  eax, 0xffffffff
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { f7c10000ffff 0f8569010000 803a00 0f8460010000 }
            // n = 4, score = 200
            //   f7c10000ffff         | test                ecx, 0xffff0000
            //   0f8569010000         | jne                 0x16f
            //   803a00               | cmp                 byte ptr [edx], 0
            //   0f8460010000         | je                  0x166

        $sequence_5 = { 85c9 745b 8b0d???????? 85c9 7451 8b0d???????? 85c9 }
            // n = 7, score = 200
            //   85c9                 | test                ecx, ecx
            //   745b                 | je                  0x5d
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx
            //   7451                 | je                  0x53
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_6 = { 33c0 83e103 f3a4 8b7c246c 83c9ff }
            // n = 5, score = 200
            //   33c0                 | xor                 eax, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b7c246c             | mov                 edi, dword ptr [esp + 0x6c]
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_7 = { 56 57 8944240c 884c2410 b91e000000 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   884c2410             | mov                 byte ptr [esp + 0x10], cl
            //   b91e000000           | mov                 ecx, 0x1e

        $sequence_8 = { 8bc1 48897c2440 4c897c2448 41f7f0 85d2 7405 }
            // n = 6, score = 100
            //   8bc1                 | dec                 eax
            //   48897c2440           | mov                 dword ptr [esp + 0x20], eax
            //   4c897c2448           | mov                 dword ptr [ebp + 3], 0x28
            //   41f7f0               | dec                 eax
            //   85d2                 | mov                 dword ptr [ebp + 7], 0x42000042
            //   7405                 | mov                 dword ptr [ebp + 0xf], 0x20

        $sequence_9 = { 837d0800 7605 33c9 668908 488b4d40 4885c9 7405 }
            // n = 7, score = 100
            //   837d0800             | inc                 ecx
            //   7605                 | test                bl, 0x10
            //   33c9                 | cmp                 dword ptr [ebp + 8], 0
            //   668908               | jbe                 7
            //   488b4d40             | xor                 ecx, ecx
            //   4885c9               | mov                 word ptr [eax], cx
            //   7405                 | dec                 eax

        $sequence_10 = { c3 0ac1 418800 b80f000000 }
            // n = 4, score = 100
            //   c3                   | dec                 eax
            //   0ac1                 | mov                 dword ptr [esp + 0x470], edi
            //   418800               | xor                 edx, edx
            //   b80f000000           | inc                 ecx

        $sequence_11 = { 0f1f840000000000 4963c2 4c8bc0 49c1f810 0fb7f8 48c1e705 4a8b04c1 }
            // n = 7, score = 100
            //   0f1f840000000000     | sub                 esp, 0x20
            //   4963c2               | dec                 eax
            //   4c8bc0               | lea                 eax, [0x17337]
            //   49c1f810             | mov                 ebx, edx
            //   0fb7f8               | dec                 eax
            //   48c1e705             | mov                 edi, ecx
            //   4a8b04c1             | dec                 eax

        $sequence_12 = { 740f eb07 4c8d05c41effff 448823 48ffc3 4c3b6de8 }
            // n = 6, score = 100
            //   740f                 | dec                 eax
            //   eb07                 | mov                 ecx, eax
            //   4c8d05c41effff       | dec                 eax
            //   448823               | mov                 ecx, edi
            //   48ffc3               | mov                 eax, dword ptr [ebp - 0x51]
            //   4c3b6de8             | dec                 eax

        $sequence_13 = { 4883ec20 488d0537730100 8bda 488bf9 488901 }
            // n = 5, score = 100
            //   4883ec20             | push                esi
            //   488d0537730100       | inc                 ecx
            //   8bda                 | push                edi
            //   488bf9               | dec                 eax
            //   488901               | sub                 esp, 0xd0

        $sequence_14 = { ffc0 3bf8 7ce0 488b742438 488b0b }
            // n = 5, score = 100
            //   ffc0                 | je                  0x11
            //   3bf8                 | ret                 
            //   7ce0                 | or                  al, cl
            //   488b742438           | inc                 ecx
            //   488b0b               | mov                 byte ptr [eax], al

        $sequence_15 = { 4889bc2470040000 ff15???????? 33d2 41b900300000 41b800001000 488bc8 c744242004000000 }
            // n = 7, score = 100
            //   4889bc2470040000     | dec                 eax
            //   ff15????????         |                     
            //   33d2                 | lea                 ecx, [esp + 0x50]
            //   41b900300000         | dec                 eax
            //   41b800001000         | mov                 ecx, esi
            //   488bc8               | mov                 dword ptr [esp + 0x28], 0x28
            //   c744242004000000     | mov                 dword ptr [ebp - 1], 0x40

        $sequence_16 = { 7209 488b4d0f e8???????? 488bcb e8???????? 0fb6d8 }
            // n = 6, score = 100
            //   7209                 | mov                 dword ptr [eax + 0x18], esi
            //   488b4d0f             | add                 ebx, 4
            //   e8????????           |                     
            //   488bcb               | or                  ecx, 0xffffffff
            //   e8????????           |                     
            //   0fb6d8               | mov                 dword ptr [ebx], edx

        $sequence_17 = { 85d2 7405 2bca 4103c8 448bc1 488bd5 }
            // n = 6, score = 100
            //   85d2                 | mov                 ecx, dword ptr [ebp + 0x40]
            //   7405                 | dec                 eax
            //   2bca                 | test                ecx, ecx
            //   4103c8               | je                  0xa
            //   448bc1               | test                edx, edx
            //   488bd5               | je                  7

        $sequence_18 = { 8bc3 4584db 0f886c010000 41f6c310 }
            // n = 4, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   4584db               | inc                 ebp
            //   0f886c010000         | test                bl, bl
            //   41f6c310             | js                  0x172

        $sequence_19 = { 488bc8 e8???????? 488bcf e8???????? 8b45af }
            // n = 5, score = 100
            //   488bc8               | mov                 eax, 0xf
            //   e8????????           |                     
            //   488bcf               | push                edi
            //   e8????????           |                     
            //   8b45af               | inc                 ecx

        $sequence_20 = { 33d2 448d4202 488bcb e8???????? 90 488d05e6240100 }
            // n = 6, score = 100
            //   33d2                 | inc                 ebp
            //   448d4202             | xor                 esi, esi
            //   488bcb               | inc                 esp
            //   e8????????           |                     
            //   90                   | mov                 dword ptr [esp + 0x60], esi
            //   488d05e6240100       | dec                 esp

        $sequence_21 = { 4c8d15cfea0a00 4885c0 7404 4c8d5010 8bcb }
            // n = 5, score = 100
            //   4c8d15cfea0a00       | mov                 eax, dword ptr [esp + 0x40]
            //   4885c0               | add                 ebx, 4
            //   7404                 | mov                 dword ptr [ebx], eax
            //   4c8d5010             | xor                 eax, eax
            //   8bcb                 | inc                 eax

        $sequence_22 = { 488bce c744242828000000 c745ff40000000 4889442420 c7450328000000 48c7450742000042 c7450f20000000 }
            // n = 7, score = 100
            //   488bce               | mov                 eax, ecx
            //   c744242828000000     | dec                 eax
            //   c745ff40000000       | mov                 edx, ebp
            //   4889442420           | sub                 ecx, 4
            //   c7450328000000       | dec                 ecx
            //   48c7450742000042     | dec                 ecx
            //   c7450f20000000       | jne                 0xffffffe3

        $sequence_23 = { 83e904 49ffc9 75de 488d4c2450 }
            // n = 4, score = 100
            //   83e904               | sub                 ecx, edx
            //   49ffc9               | inc                 ecx
            //   75de                 | add                 ecx, eax
            //   488d4c2450           | inc                 esp

    condition:
        7 of them and filesize < 1581056
}