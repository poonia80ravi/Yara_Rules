rule win_laturo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.laturo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.laturo"
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
        $sequence_0 = { 83781000 753c 48837c242800 7412 488b442428 }
            // n = 5, score = 200
            //   83781000             | dec                 eax
            //   753c                 | cmp                 eax, 0x32
            //   48837c242800         | jbe                 0xd
            //   7412                 | jae                 0x2a
            //   488b442428           | mov                 eax, dword ptr [esp]

        $sequence_1 = { 85c0 743d 488b8424a8000000 8b4021 83c820 }
            // n = 5, score = 200
            //   85c0                 | dec                 eax
            //   743d                 | test                eax, eax
            //   488b8424a8000000     | je                  0xe
            //   8b4021               | test                eax, eax
            //   83c820               | je                  0x3f

        $sequence_2 = { 7328 8b0424 488b4c2420 0fb60401 b901000000 486bc900 }
            // n = 6, score = 200
            //   7328                 | mov                 dword ptr [esp + 0x48], eax
            //   8b0424               | dec                 eax
            //   488b4c2420           | lea                 ecx, [esp + 0x38]
            //   0fb60401             | test                eax, eax
            //   b901000000           | add                 eax, dword ptr [esp + 0x24]
            //   486bc900             | mov                 eax, eax

        $sequence_3 = { b905000000 4c8d05d1860000 488d15d2860000 e8???????? 8bcb 4885c0 740c }
            // n = 7, score = 200
            //   b905000000           | mov                 ecx, 5
            //   4c8d05d1860000       | dec                 esp
            //   488d15d2860000       | lea                 eax, [0x86d1]
            //   e8????????           |                     
            //   8bcb                 | dec                 eax
            //   4885c0               | lea                 edx, [0x86d2]
            //   740c                 | mov                 ecx, ebx

        $sequence_4 = { 0fb6400c 85c0 7422 488d055c7d0100 }
            // n = 4, score = 200
            //   0fb6400c             | dec                 eax
            //   85c0                 | mov                 ecx, dword ptr [esp + 0x20]
            //   7422                 | movzx               eax, byte ptr [ecx + eax]
            //   488d055c7d0100       | mov                 ecx, 1

        $sequence_5 = { 03442424 8bc0 4883f832 7607 }
            // n = 4, score = 200
            //   03442424             | mov                 dword ptr [esp + 0x40], eax
            //   8bc0                 | dec                 eax
            //   4883f832             | mov                 eax, dword ptr [esp + 0x30]
            //   7607                 | dec                 eax

        $sequence_6 = { 750b 0fb6442406 d0e0 88442406 0fb6442405 83f803 }
            // n = 6, score = 200
            //   750b                 | dec                 eax
            //   0fb6442406           | imul                ecx, ecx, 0
            //   d0e0                 | cmp                 dword ptr [eax + 0x10], 0
            //   88442406             | jne                 0x3e
            //   0fb6442405           | dec                 eax
            //   83f803               | cmp                 dword ptr [esp + 0x28], 0

        $sequence_7 = { 4889442440 488b442430 4889442448 488d4c2438 e8???????? 85c0 }
            // n = 6, score = 200
            //   4889442440           | dec                 eax
            //   488b442430           | mov                 eax, dword ptr [esp + 0xa8]
            //   4889442448           | mov                 eax, dword ptr [eax + 0x21]
            //   488d4c2438           | or                  eax, 0x20
            //   e8????????           |                     
            //   85c0                 | dec                 eax

        $sequence_8 = { 897b0c 897b10 8945ec e8???????? f745c000100000 8bc8 }
            // n = 6, score = 100
            //   897b0c               | mov                 dword ptr [ebx + 0xc], edi
            //   897b10               | mov                 dword ptr [ebx + 0x10], edi
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   e8????????           |                     
            //   f745c000100000       | test                dword ptr [ebp - 0x40], 0x1000
            //   8bc8                 | mov                 ecx, eax

        $sequence_9 = { 83e20f 7640 8b5e08 0fb6440e20 }
            // n = 4, score = 100
            //   83e20f               | and                 edx, 0xf
            //   7640                 | jbe                 0x42
            //   8b5e08               | mov                 ebx, dword ptr [esi + 8]
            //   0fb6440e20           | movzx               eax, byte ptr [esi + ecx + 0x20]

        $sequence_10 = { 0f8420010000 8b15???????? 83feff 7403 8d5601 33c0 }
            // n = 6, score = 100
            //   0f8420010000         | je                  0x126
            //   8b15????????         |                     
            //   83feff               | cmp                 esi, -1
            //   7403                 | je                  5
            //   8d5601               | lea                 edx, [esi + 1]
            //   33c0                 | xor                 eax, eax

        $sequence_11 = { ff15???????? 47 3b7e08 72c7 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   47                   | inc                 edi
            //   3b7e08               | cmp                 edi, dword ptr [esi + 8]
            //   72c7                 | jb                  0xffffffc9

        $sequence_12 = { c645f404 eb2b c645f401 eb25 f6c110 7410 }
            // n = 6, score = 100
            //   c645f404             | mov                 byte ptr [ebp - 0xc], 4
            //   eb2b                 | jmp                 0x2d
            //   c645f401             | mov                 byte ptr [ebp - 0xc], 1
            //   eb25                 | jmp                 0x27
            //   f6c110               | test                cl, 0x10
            //   7410                 | je                  0x12

        $sequence_13 = { 56 6a01 8bfa 8bd9 68???????? 897df8 ff15???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   6a01                 | push                1
            //   8bfa                 | mov                 edi, edx
            //   8bd9                 | mov                 ebx, ecx
            //   68????????           |                     
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   ff15????????         |                     

        $sequence_14 = { 897de4 eb35 8ac2 24fc }
            // n = 4, score = 100
            // 
            //   eb35                 | jmp                 0x37
            //   8ac2                 | mov                 al, dl
            //   24fc                 | and                 al, 0xfc

        $sequence_15 = { 8bf7 8b07 eb02 8b03 }
            // n = 4, score = 100
            //   8bf7                 | mov                 esi, edi
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   eb02                 | jmp                 4
            //   8b03                 | mov                 eax, dword ptr [ebx]

    condition:
        7 of them and filesize < 253952
}