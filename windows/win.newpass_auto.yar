rule win_newpass_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.newpass."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newpass"
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
        $sequence_0 = { 7438 4183e6bf 4489742450 4883bd1802000010 720c 488b8d00020000 }
            // n = 6, score = 500
            //   7438                 | dec                 eax
            //   4183e6bf             | lea                 edx, [0x61754]
            //   4489742450           | mov                 ecx, 0x114
            //   4883bd1802000010     | je                  0x777
            //   720c                 | jne                 0x693
            //   488b8d00020000       | dec                 eax

        $sequence_1 = { b99b000000 e8???????? 488bd0 4c8bc2 ba0c030000 488d8c2480000000 e8???????? }
            // n = 7, score = 500
            //   b99b000000           | movzx               eax, byte ptr [esi + 0xd]
            //   e8????????           |                     
            //   488bd0               | movzx               eax, byte ptr [esi + 0xb]
            //   4c8bc2               | mov                 byte ptr [ebp - 0x25], al
            //   ba0c030000           | movzx               eax, byte ptr [esi + 0xc]
            //   488d8c2480000000     | mov                 byte ptr [ebp - 0x24], al
            //   e8????????           |                     

        $sequence_2 = { 41b900000080 4c8d45a8 488d542438 488d4d10 e8???????? 90 488b8d30100000 }
            // n = 7, score = 500
            //   41b900000080         | jmp                 0xac4
            //   4c8d45a8             | dec                 eax
            //   488d542438           | lea                 eax, [0x81eab]
            //   488d4d10             | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 edx, eax
            //   488b8d30100000       | dec                 eax

        $sequence_3 = { eb4c 807b0800 7539 488b0b 4885c9 742a 488b4138 }
            // n = 7, score = 500
            //   eb4c                 | dec                 eax
            //   807b0800             | cmp                 eax, dword ptr [ebx + 0x20]
            //   7539                 | jb                  0xda5
            //   488b0b               | mov                 edx, 1
            //   4885c9               | dec                 eax
            //   742a                 | mov                 ecx, ebx
            //   488b4138             | inc                 ebx

        $sequence_4 = { 4183f904 7ca8 eb02 33d2 837b3000 0f85cc010000 448d920028ffff }
            // n = 7, score = 500
            //   4183f904             | jmp                 0xca8
            //   7ca8                 | dec                 eax
            //   eb02                 | lea                 eax, [0x81038]
            //   33d2                 | dec                 eax
            //   837b3000             | mov                 edx, eax
            //   0f85cc010000         | dec                 eax
            //   448d920028ffff       | lea                 edx, [0x85c4b]

        $sequence_5 = { 488d0d70270500 488905???????? 4883c428 e9???????? 4883ec28 e8???????? }
            // n = 6, score = 500
            //   488d0d70270500       | cmp                 dword ptr [ebx + 0x18], 0x10
            //   488905????????       |                     
            //   4883c428             | jb                  0x439
            //   e9????????           |                     
            //   4883ec28             | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { c3 4055 4883ec20 488bea 8b4550 2500100000 85c0 }
            // n = 7, score = 500
            //   c3                   | xor                 al, 0xc6
            //   4055                 | and                 eax, 0x800000ff
            //   4883ec20             | jge                 0x436
            //   488bea               | dec                 eax
            //   8b4550               | or                  eax, 0xffffff00
            //   2500100000           | inc                 eax
            //   85c0                 | inc                 ecx

        $sequence_7 = { 7326 4863c9 488d1504120400 488bc1 83e11f 48c1f805 486bc958 }
            // n = 7, score = 500
            //   7326                 | je                  0x768
            //   4863c9               | dec                 eax
            //   488d1504120400       | mov                 eax, dword ptr [ebx]
            //   488bc1               | dec                 eax
            //   83e11f               | mov                 edx, edi
            //   48c1f805             | dec                 eax
            //   486bc958             | mov                 dword ptr [eax + 8], eax

        $sequence_8 = { 4883ec20 488bea 4c8d0da032fbff 41b803000000 ba20000000 488d8dd0000000 e8???????? }
            // n = 7, score = 500
            //   4883ec20             | mov                 ecx, esi
            //   488bea               | dec                 eax
            //   4c8d0da032fbff       | test                eax, eax
            //   41b803000000         | je                  0x1371
            //   ba20000000           | dec                 eax
            //   488d8dd0000000       | lea                 edx, [ebp + 0x520]
            //   e8????????           |                     

        $sequence_9 = { 8b4620 83f8ff 7508 f6461c10 7520 3bc0 488b5c2440 }
            // n = 7, score = 500
            //   8b4620               | add                 byte ptr [ebp - 0x4bfffc74], bh
            //   83f8ff               | mov                 word ptr [ebx], es
            //   7508                 | add                 byte ptr [edi - 0x53fffc74], cl
            //   f6461c10             | mov                 word ptr [ebx], es
            //   7520                 | add                 byte ptr [ecx - 0x6afffc74], ah
            //   3bc0                 | mov                 word ptr [ebx], es
            //   488b5c2440           | add                 byte ptr [eax + 0x6600038c], al

    condition:
        7 of them and filesize < 1286144
}