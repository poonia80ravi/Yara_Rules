rule win_alureon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.alureon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alureon"
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
        $sequence_0 = { 83e5e0 33c0 4c 8bd1 48 8d7d20 44 }
            // n = 7, score = 200
            //   83e5e0               | and                 ebp, 0xffffffe0
            //   33c0                 | xor                 eax, eax
            //   4c                   | dec                 esp
            //   8bd1                 | mov                 edx, ecx
            //   48                   | dec                 eax
            //   8d7d20               | lea                 edi, [ebp + 0x20]
            //   44                   | inc                 esp

        $sequence_1 = { 03cb 0f84fa010000 41 8b81b0000000 85c0 7460 }
            // n = 6, score = 200
            //   03cb                 | add                 ecx, ebx
            //   0f84fa010000         | je                  0x200
            //   41                   | inc                 ecx
            //   8b81b0000000         | mov                 eax, dword ptr [ecx + 0xb0]
            //   85c0                 | test                eax, eax
            //   7460                 | je                  0x62

        $sequence_2 = { be???????? 8dbda8fdffff a5 a5 33db }
            // n = 5, score = 200
            //   be????????           |                     
            //   8dbda8fdffff         | lea                 edi, [ebp - 0x258]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   33db                 | xor                 ebx, ebx

        $sequence_3 = { 394df8 72e2 8b7a3c 03fa 897df4 0f84e9000000 8b87a0000000 }
            // n = 7, score = 200
            //   394df8               | cmp                 dword ptr [ebp - 8], ecx
            //   72e2                 | jb                  0xffffffe4
            //   8b7a3c               | mov                 edi, dword ptr [edx + 0x3c]
            //   03fa                 | add                 edi, edx
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   0f84e9000000         | je                  0xef
            //   8b87a0000000         | mov                 eax, dword ptr [edi + 0xa0]

        $sequence_4 = { 8b87a0000000 85c0 745a 8bb7a4000000 03c2 eb4c }
            // n = 6, score = 200
            //   8b87a0000000         | mov                 eax, dword ptr [edi + 0xa0]
            //   85c0                 | test                eax, eax
            //   745a                 | je                  0x5c
            //   8bb7a4000000         | mov                 esi, dword ptr [edi + 0xa4]
            //   03c2                 | add                 eax, edx
            //   eb4c                 | jmp                 0x4e

        $sequence_5 = { 41 8bcb f3aa 8b8c2420010000 41 8d43d8 }
            // n = 6, score = 200
            //   41                   | inc                 ecx
            //   8bcb                 | mov                 ecx, ebx
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   8b8c2420010000       | mov                 ecx, dword ptr [esp + 0x120]
            //   41                   | inc                 ecx
            //   8d43d8               | lea                 eax, [ebx - 0x28]

        $sequence_6 = { 8d8dc6fdffff 33c0 894d08 8b7508 }
            // n = 4, score = 200
            //   8d8dc6fdffff         | lea                 ecx, [ebp - 0x23a]
            //   33c0                 | xor                 eax, eax
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_7 = { 88542443 8bd1 884c2445 8bc8 }
            // n = 4, score = 200
            //   88542443             | mov                 byte ptr [esp + 0x43], dl
            //   8bd1                 | mov                 edx, ecx
            //   884c2445             | mov                 byte ptr [esp + 0x45], cl
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { 8d8df8fdffff 51 53 53 6a1a 53 ffd0 }
            // n = 7, score = 100
            //   8d8df8fdffff         | lea                 ecx, [ebp - 0x208]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6a1a                 | push                0x1a
            //   53                   | push                ebx
            //   ffd0                 | call                eax

        $sequence_9 = { 59 59 8845ff 7512 8d85b8fbffff 50 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   7512                 | jne                 0x14
            //   8d85b8fbffff         | lea                 eax, [ebp - 0x448]
            //   50                   | push                eax

        $sequence_10 = { eb28 ffb424dc000000 ff15???????? 8d442414 50 6a24 8d8424cc000000 }
            // n = 7, score = 100
            //   eb28                 | jmp                 0x2a
            //   ffb424dc000000       | push                dword ptr [esp + 0xdc]
            //   ff15????????         |                     
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   50                   | push                eax
            //   6a24                 | push                0x24
            //   8d8424cc000000       | lea                 eax, [esp + 0xcc]

        $sequence_11 = { 56 68???????? ff15???????? 8bf0 8d442404 50 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   8d442404             | lea                 eax, [esp + 4]
            //   50                   | push                eax

        $sequence_12 = { be00100000 56 33db 6a08 885dff 8975f4 ff15???????? }
            // n = 7, score = 100
            //   be00100000           | mov                 esi, 0x1000
            //   56                   | push                esi
            //   33db                 | xor                 ebx, ebx
            //   6a08                 | push                8
            //   885dff               | mov                 byte ptr [ebp - 1], bl
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   ff15????????         |                     

        $sequence_13 = { 50 ff15???????? 68b6100000 bf???????? 57 e8???????? 83c418 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   68b6100000           | push                0x10b6
            //   bf????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_14 = { 66c74424563000 c744245884214000 c644245c68 e8???????? 6a01 89442461 a1???????? }
            // n = 7, score = 100
            //   66c74424563000       | mov                 word ptr [esp + 0x56], 0x30
            //   c744245884214000     | mov                 dword ptr [esp + 0x58], 0x402184
            //   c644245c68           | mov                 byte ptr [esp + 0x5c], 0x68
            //   e8????????           |                     
            //   6a01                 | push                1
            //   89442461             | mov                 dword ptr [esp + 0x61], eax
            //   a1????????           |                     

        $sequence_15 = { 8d44247c 50 6803001f00 8d44242c 50 66c74424580a00 }
            // n = 6, score = 100
            //   8d44247c             | lea                 eax, [esp + 0x7c]
            //   50                   | push                eax
            //   6803001f00           | push                0x1f0003
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   50                   | push                eax
            //   66c74424580a00       | mov                 word ptr [esp + 0x58], 0xa

    condition:
        7 of them and filesize < 278528
}