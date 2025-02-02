rule win_coldseal_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Detects win.coldseal."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coldseal"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = "20220411"
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
        $sequence_0 = { 8bf0 6a00 6a00 6aff 68???????? 6a00 }
            // n = 6, score = 2900
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6aff                 | push                -1
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_1 = { 51 6a40 8b15???????? ffd2 }
            // n = 4, score = 2600
            //   51                   | push                ecx
            //   6a40                 | push                0x40
            //   8b15????????         |                     
            //   ffd2                 | call                edx

        $sequence_2 = { 6a05 6a40 a1???????? ffd0 }
            // n = 4, score = 2500
            //   6a05                 | push                5
            //   6a40                 | push                0x40
            //   a1????????           |                     
            //   ffd0                 | call                eax

        $sequence_3 = { 51 6a00 6a00 8b15???????? ffd2 }
            // n = 5, score = 2300
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b15????????         |                     
            //   ffd2                 | call                edx

        $sequence_4 = { 8b15???????? ffd2 50 a1???????? }
            // n = 4, score = 2200
            //   8b15????????         |                     
            //   ffd2                 | call                edx
            //   50                   | push                eax
            //   a1????????           |                     

        $sequence_5 = { 68???????? 6a00 a1???????? ffd0 }
            // n = 4, score = 2200
            //   68????????           |                     
            //   6a00                 | push                0
            //   a1????????           |                     
            //   ffd0                 | call                eax

        $sequence_6 = { 52 a1???????? ffd0 85c0 }
            // n = 4, score = 2200
            //   52                   | push                edx
            //   a1????????           |                     
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_7 = { 8b45fc 50 8b0d???????? ffd1 }
            // n = 4, score = 2100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   8b0d????????         |                     
            //   ffd1                 | call                ecx

        $sequence_8 = { 8b15???????? a1???????? 03423c a3???????? }
            // n = 4, score = 2100
            //   8b15????????         |                     
            //   a1????????           |                     
            //   03423c               | add                 eax, dword ptr [edx + 0x3c]
            //   a3????????           |                     

        $sequence_9 = { a1???????? ffd0 50 8b0d???????? }
            // n = 4, score = 2000
            //   a1????????           |                     
            //   ffd0                 | call                eax
            //   50                   | push                eax
            //   8b0d????????         |                     

        $sequence_10 = { 52 6a08 a1???????? ffd0 }
            // n = 4, score = 1900
            //   52                   | push                edx
            //   6a08                 | push                8
            //   a1????????           |                     
            //   ffd0                 | call                eax

        $sequence_11 = { 8b5118 8955dc c745d400000000 eb09 8b45d4 }
            // n = 5, score = 1800
            //   8b5118               | mov                 edx, dword ptr [ecx + 0x18]
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   c745d400000000       | mov                 dword ptr [ebp - 0x2c], 0
            //   eb09                 | jmp                 0xb
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]

        $sequence_12 = { 8b4dfc 51 8b15???????? ffd2 }
            // n = 4, score = 1800
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   8b15????????         |                     
            //   ffd2                 | call                edx

        $sequence_13 = { 8b45f4 8945f4 8b4df4 83c101 894df4 }
            // n = 5, score = 1700
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   83c101               | add                 ecx, 1
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_14 = { 8955f8 780f 837df805 7f09 }
            // n = 4, score = 1700
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   780f                 | js                  0x11
            //   837df805             | cmp                 dword ptr [ebp - 8], 5
            //   7f09                 | jg                  0xb

        $sequence_15 = { 8b45f8 8b4dec 030c90 894dd0 }
            // n = 4, score = 1700
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   030c90               | add                 ecx, dword ptr [eax + edx*4]
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx

        $sequence_16 = { 8915???????? a1???????? 0fb708 81f94d5a0000 }
            // n = 4, score = 1600
            //   8915????????         |                     
            //   a1????????           |                     
            //   0fb708               | movzx               ecx, word ptr [eax]
            //   81f94d5a0000         | cmp                 ecx, 0x5a4d

        $sequence_17 = { 8b4de0 8b55ec 035120 8955f8 }
            // n = 4, score = 1500
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   035120               | add                 edx, dword ptr [ecx + 0x20]
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_18 = { 039485f8fbffff 81e2ff000080 7908 4a 81ca00ffffff 42 }
            // n = 6, score = 1300
            //   039485f8fbffff       | add                 edx, dword ptr [ebp + eax*4 - 0x408]
            //   81e2ff000080         | and                 edx, 0x800000ff
            //   7908                 | jns                 0xa
            //   4a                   | dec                 edx
            //   81ca00ffffff         | or                  edx, 0xffffff00
            //   42                   | inc                 edx

        $sequence_19 = { e9???????? c785f4fbffff00000000 8b85f4fbffff 8945fc c745f800000000 }
            // n = 5, score = 1300
            //   e9????????           |                     
            //   c785f4fbffff00000000     | mov    dword ptr [ebp - 0x40c], 0
            //   8b85f4fbffff         | mov                 eax, dword ptr [ebp - 0x40c]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

        $sequence_20 = { 8b948df8fbffff 8b85f4fbffff 039485f8fbffff 81e2ff000080 }
            // n = 4, score = 1300
            //   8b948df8fbffff       | mov                 edx, dword ptr [ebp + ecx*4 - 0x408]
            //   8b85f4fbffff         | mov                 eax, dword ptr [ebp - 0x40c]
            //   039485f8fbffff       | add                 edx, dword ptr [ebp + eax*4 - 0x408]
            //   81e2ff000080         | and                 edx, 0x800000ff

        $sequence_21 = { 8b95f4fbffff 898c95f8fbffff e9???????? c785f4fbffff00000000 }
            // n = 4, score = 1300
            //   8b95f4fbffff         | mov                 edx, dword ptr [ebp - 0x40c]
            //   898c95f8fbffff       | mov                 dword ptr [ebp + edx*4 - 0x408], ecx
            //   e9????????           |                     
            //   c785f4fbffff00000000     | mov    dword ptr [ebp - 0x40c], 0

        $sequence_22 = { 6a00 6a40 6800300000 68e8030000 }
            // n = 4, score = 1100
            //   6a00                 | push                0
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   68e8030000           | push                0x3e8

        $sequence_23 = { 50 ff15???????? a3???????? 8ac6 }
            // n = 4, score = 800
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     
            //   8ac6                 | mov                 al, dh

        $sequence_24 = { 8ac6 8ac6 8ac6 fec8 }
            // n = 4, score = 600
            //   8ac6                 | mov                 al, dh
            //   8ac6                 | mov                 al, dh
            //   8ac6                 | mov                 al, dh
            //   fec8                 | dec                 al

        $sequence_25 = { fec8 0fbec6 f6d8 3ac6 }
            // n = 4, score = 600
            //   fec8                 | dec                 al
            //   0fbec6               | movsx               eax, dh
            //   f6d8                 | neg                 al
            //   3ac6                 | cmp                 al, dh

        $sequence_26 = { 3ac6 8ac6 3ac6 0fadd8 }
            // n = 4, score = 600
            //   3ac6                 | cmp                 al, dh
            //   8ac6                 | mov                 al, dh
            //   3ac6                 | cmp                 al, dh
            //   0fadd8               | shrd                eax, ebx, cl

        $sequence_27 = { 3ac6 0fc8 0fafc3 84f7 }
            // n = 4, score = 600
            //   3ac6                 | cmp                 al, dh
            //   0fc8                 | bswap               eax
            //   0fafc3               | imul                eax, ebx
            //   84f7                 | test                bh, dh

        $sequence_28 = { 3ac6 0fbec6 0fa3d8 3ac6 }
            // n = 4, score = 500
            //   3ac6                 | cmp                 al, dh
            //   0fbec6               | movsx               eax, dh
            //   0fa3d8               | bt                  eax, ebx
            //   3ac6                 | cmp                 al, dh

        $sequence_29 = { 8b400c c1e80d 83e001 c3 6a10 68???????? }
            // n = 6, score = 400
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   c1e80d               | shr                 eax, 0xd
            //   83e001               | and                 eax, 1
            //   c3                   | ret                 
            //   6a10                 | push                0x10
            //   68????????           |                     

        $sequence_30 = { ebcb 8bff 55 8bec a1???????? 85c0 7575 }
            // n = 7, score = 400
            //   ebcb                 | jmp                 0xffffffcd
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7575                 | jne                 0x77

        $sequence_31 = { e8???????? 59 59 c3 8b11 }
            // n = 5, score = 400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   8b11                 | mov                 edx, dword ptr [ecx]

        $sequence_32 = { 23ca 890d???????? 5d c3 8b01 }
            // n = 5, score = 400
            //   23ca                 | and                 ecx, edx
            //   890d????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_33 = { 56 e8???????? 59 c3 8b01 8b400c c1e806 }
            // n = 7, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   c1e806               | shr                 eax, 6

        $sequence_34 = { c3 e9???????? e8???????? 0fb7c0 50 e8???????? }
            // n = 6, score = 400
            //   c3                   | ret                 
            //   e9????????           |                     
            //   e8????????           |                     
            //   0fb7c0               | movzx               eax, ax
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_35 = { 314205 52 d1ec b26a d937 }
            // n = 5, score = 100
            //   314205               | xor                 dword ptr [edx + 5], eax
            //   52                   | push                edx
            //   d1ec                 | shr                 esp, 1
            //   b26a                 | mov                 dl, 0x6a
            //   d937                 | fnstenv             dword ptr [edi]

        $sequence_36 = { fd ee 39df b551 e7af 9ae2dcadf43e3f }
            // n = 6, score = 100
            //   fd                   | std                 
            //   ee                   | out                 dx, al
            //   39df                 | cmp                 edi, ebx
            //   b551                 | mov                 ch, 0x51
            //   e7af                 | out                 0xaf, eax
            //   9ae2dcadf43e3f       | lcall               0x3f3e:0xf4addce2

        $sequence_37 = { 59 75dd 37 e756 caa354 72e4 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   75dd                 | jne                 0xffffffdf
            //   37                   | aaa                 
            //   e756                 | out                 0x56, eax
            //   caa354               | retf                0x54a3
            //   72e4                 | jb                  0xffffffe6

        $sequence_38 = { 44 ae 27 fa 96 59 }
            // n = 6, score = 100
            //   44                   | inc                 esp
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   27                   | daa                 
            //   fa                   | cli                 
            //   96                   | xchg                eax, esi
            //   59                   | pop                 ecx

        $sequence_39 = { 8d9af2acb3ea 6c 44 ae }
            // n = 4, score = 100
            //   8d9af2acb3ea         | lea                 ebx, dword ptr [edx - 0x154c530e]
            //   6c                   | insb                byte ptr es:[edi], dx
            //   44                   | inc                 esp
            //   ae                   | scasb               al, byte ptr es:[edi]

        $sequence_40 = { 9ae2dcadf43e3f 7622 3f 4c 3f f763bb }
            // n = 6, score = 100
            //   9ae2dcadf43e3f       | lcall               0x3f3e:0xf4addce2
            //   7622                 | jbe                 0x24
            //   3f                   | aas                 
            //   4c                   | dec                 esp
            //   3f                   | aas                 
            //   f763bb               | mul                 dword ptr [ebx - 0x45]

        $sequence_41 = { 308903005d00 000400 308903000000 0000 002a a2???????? }
            // n = 6, score = 100
            //   308903005d00         | xor                 byte ptr [ecx + 0x5d0003], cl
            //   000400               | add                 byte ptr [eax + eax], al
            //   308903000000         | xor                 byte ptr [ecx + 3], cl
            //   0000                 | add                 byte ptr [eax], al
            //   002a                 | add                 byte ptr [edx], ch
            //   a2????????           |                     

        $sequence_42 = { ca0a3e 4d 0e 314205 52 }
            // n = 5, score = 100
            //   ca0a3e               | retf                0x3e0a
            //   4d                   | dec                 ebp
            //   0e                   | push                cs
            //   314205               | xor                 dword ptr [edx + 5], eax
            //   52                   | push                edx

    condition:
        7 of them and filesize < 1190912
}