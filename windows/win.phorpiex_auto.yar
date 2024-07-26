rule win_phorpiex_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.phorpiex."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phorpiex"
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
        $sequence_0 = { 6a00 ff15???????? ff15???????? 50 e8???????? }
            // n = 5, score = 1100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_1 = { ff15???????? 85c0 740f 6a07 }
            // n = 4, score = 1100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   6a07                 | push                7

        $sequence_2 = { ff15???????? 85c0 741f 6880000000 }
            // n = 4, score = 1000
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741f                 | je                  0x21
            //   6880000000           | push                0x80

        $sequence_3 = { 6a00 6a20 6a00 6a00 6a00 8b5508 }
            // n = 6, score = 900
            //   6a00                 | push                0
            //   6a20                 | push                0x20
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_4 = { e8???????? 83c410 6a00 6a02 6a02 6a00 6a00 }
            // n = 7, score = 900
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { e8???????? 83c404 e8???????? e8???????? ff15???????? 6a00 }
            // n = 6, score = 800
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e8????????           |                     
            //   e8????????           |                     
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_6 = { 6a01 6a00 68???????? e8???????? 83c40c 33c0 }
            // n = 6, score = 800
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { e8???????? 99 b90d000000 f7f9 }
            // n = 4, score = 800
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b90d000000           | mov                 ecx, 0xd
            //   f7f9                 | idiv                ecx

        $sequence_8 = { 6a00 ff15???????? 85c0 7418 ff15???????? }
            // n = 5, score = 700
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7418                 | je                  0x1a
            //   ff15????????         |                     

        $sequence_9 = { 6a01 ff15???????? ff15???????? b001 }
            // n = 4, score = 700
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   b001                 | mov                 al, 1

        $sequence_10 = { 52 683f000f00 6a00 68???????? 6802000080 ff15???????? 85c0 }
            // n = 7, score = 700
            //   52                   | push                edx
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_11 = { 6a00 6a00 682a800000 6a00 }
            // n = 4, score = 700
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   682a800000           | push                0x802a
            //   6a00                 | push                0

        $sequence_12 = { 68???????? ff15???????? 8d85f8fdffff 50 68???????? }
            // n = 5, score = 700
            //   68????????           |                     
            //   ff15????????         |                     
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_13 = { 6a08 68???????? 6a00 68???????? }
            // n = 4, score = 700
            //   6a08                 | push                8
            //   68????????           |                     
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_14 = { ff15???????? 85c0 7522 6a00 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7522                 | jne                 0x24
            //   6a00                 | push                0

        $sequence_15 = { 0fb64c15c8 03c1 0fb74d10 99 }
            // n = 4, score = 600
            //   0fb64c15c8           | movzx               ecx, byte ptr [ebp + edx - 0x38]
            //   03c1                 | add                 eax, ecx
            //   0fb74d10             | movzx               ecx, word ptr [ebp + 0x10]
            //   99                   | cdq                 

        $sequence_16 = { 81c210270000 52 e8???????? 99 }
            // n = 4, score = 600
            //   81c210270000         | add                 edx, 0x2710
            //   52                   | push                edx
            //   e8????????           |                     
            //   99                   | cdq                 

        $sequence_17 = { 68???????? ff15???????? e9???????? 8d45fc }
            // n = 4, score = 600
            //   68????????           |                     
            //   ff15????????         |                     
            //   e9????????           |                     
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_18 = { 837dfc00 7416 8b4df8 51 ff15???????? }
            // n = 5, score = 600
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   7416                 | je                  0x18
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_19 = { 85c0 7440 6a01 ff15???????? 8945f8 }
            // n = 5, score = 600
            //   85c0                 | test                eax, eax
            //   7440                 | je                  0x42
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_20 = { 6a21 50 e8???????? c60000 }
            // n = 4, score = 500
            //   6a21                 | push                0x21
            //   50                   | push                eax
            //   e8????????           |                     
            //   c60000               | mov                 byte ptr [eax], 0

        $sequence_21 = { 7504 83c8ff c3 8b542404 }
            // n = 4, score = 500
            //   7504                 | jne                 6
            //   83c8ff               | or                  eax, 0xffffffff
            //   c3                   | ret                 
            //   8b542404             | mov                 edx, dword ptr [esp + 4]

        $sequence_22 = { 50 e8???????? 59 59 85c0 7573 }
            // n = 6, score = 500
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7573                 | jne                 0x75

        $sequence_23 = { ff15???????? 3db7000000 7508 6a00 ff15???????? 6804010000 }
            // n = 6, score = 500
            //   ff15????????         |                     
            //   3db7000000           | cmp                 eax, 0xb7
            //   7508                 | jne                 0xa
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6804010000           | push                0x104

        $sequence_24 = { 52 ffd7 6a00 8d442410 50 6a00 }
            // n = 6, score = 400
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   6a00                 | push                0
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_25 = { e8???????? 83c40c e8???????? 99 b960ea0000 }
            // n = 5, score = 400
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b960ea0000           | mov                 ecx, 0xea60

        $sequence_26 = { 56 e8???????? 83c410 83ef01 75de 5f }
            // n = 6, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83ef01               | sub                 edi, 1
            //   75de                 | jne                 0xffffffe0
            //   5f                   | pop                 edi

        $sequence_27 = { 6800000040 8d842420010000 50 ff15???????? 8bf0 83feff 741e }
            // n = 7, score = 400
            //   6800000040           | push                0x40000000
            //   8d842420010000       | lea                 eax, [esp + 0x120]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   741e                 | je                  0x20

        $sequence_28 = { 50 8d45ec 50 6805000020 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   6805000020           | push                0x20000005

        $sequence_29 = { 68e8030000 ff15???????? e8???????? be???????? }
            // n = 4, score = 300
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   e8????????           |                     
            //   be????????           |                     

        $sequence_30 = { 663bc2 72f7 53 33c0 56 57 }
            // n = 6, score = 300
            //   663bc2               | cmp                 ax, dx
            //   72f7                 | jb                  0xfffffff9
            //   53                   | push                ebx
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_31 = { 8d45f8 50 8d45e4 50 6805000020 }
            // n = 5, score = 200
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   6805000020           | push                0x20000005

    condition:
        7 of them and filesize < 2490368
}