rule win_plugx_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.plugx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plugx"
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
        $sequence_0 = { 55 8bec 8b450c 81780402700000 }
            // n = 4, score = 1300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   81780402700000       | cmp                 dword ptr [eax + 4], 0x7002

        $sequence_1 = { 53 6a00 6a00 6a02 ffd0 }
            // n = 5, score = 1300
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   ffd0                 | call                eax

        $sequence_2 = { 41 3bca 7ce0 3bca }
            // n = 4, score = 1300
            //   41                   | inc                 ecx
            //   3bca                 | cmp                 ecx, edx
            //   7ce0                 | jl                  0xffffffe2
            //   3bca                 | cmp                 ecx, edx

        $sequence_3 = { 0145f4 8b45fc 0fafc3 33d2 }
            // n = 4, score = 1300
            //   0145f4               | add                 dword ptr [ebp - 0xc], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fafc3               | imul                eax, ebx
            //   33d2                 | xor                 edx, edx

        $sequence_4 = { 33d2 f7f3 33d2 8945fc }
            // n = 4, score = 1300
            //   33d2                 | xor                 edx, edx
            //   f7f3                 | div                 ebx
            //   33d2                 | xor                 edx, edx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_5 = { 55 8bec a1???????? 83ec5c 53 }
            // n = 5, score = 1300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   83ec5c               | sub                 esp, 0x5c
            //   53                   | push                ebx

        $sequence_6 = { 56 8b750c 8b4604 050070ffff }
            // n = 4, score = 1300
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   050070ffff           | add                 eax, 0xffff7000

        $sequence_7 = { 55 8bec 51 56 57 6a1c 8bf8 }
            // n = 7, score = 1300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a1c                 | push                0x1c
            //   8bf8                 | mov                 edi, eax

        $sequence_8 = { 6a00 6a04 6a00 6a01 6800000040 57 }
            // n = 6, score = 700
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000040           | push                0x40000000
            //   57                   | push                edi

        $sequence_9 = { 6819000200 6a00 6a00 6a00 51 }
            // n = 5, score = 600
            //   6819000200           | push                0x20019
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   51                   | push                ecx

        $sequence_10 = { 57 e8???????? eb0c e8???????? }
            // n = 4, score = 500
            //   57                   | push                edi
            //   e8????????           |                     
            //   eb0c                 | jmp                 0xe
            //   e8????????           |                     

        $sequence_11 = { ffd7 a3???????? 56 ffd0 }
            // n = 4, score = 400
            //   ffd7                 | call                edi
            //   a3????????           |                     
            //   56                   | push                esi
            //   ffd0                 | call                eax

        $sequence_12 = { 6819000200 6a00 52 51 }
            // n = 4, score = 300
            //   6819000200           | push                0x20019
            //   6a00                 | push                0
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_13 = { 50 ffd6 a3???????? 57 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   57                   | push                edi

        $sequence_14 = { ffd6 a3???????? 6a64 ffd0 }
            // n = 4, score = 200
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   6a64                 | push                0x64
            //   ffd0                 | call                eax

        $sequence_15 = { ffd7 a3???????? 68e8030000 ffd0 }
            // n = 4, score = 200
            //   ffd7                 | call                edi
            //   a3????????           |                     
            //   68e8030000           | push                0x3e8
            //   ffd0                 | call                eax

        $sequence_16 = { c705????????01000000 6a04 58 6bc000 c7803cc0021002000000 6a04 }
            // n = 6, score = 100
            //   c705????????01000000     |     
            //   6a04                 | push                4
            //   58                   | pop                 eax
            //   6bc000               | imul                eax, eax, 0
            //   c7803cc0021002000000     | mov    dword ptr [eax + 0x1002c03c], 2
            //   6a04                 | push                4

        $sequence_17 = { 66894daa ba25000000 668955ac b832000000 668945ae b92e000000 }
            // n = 6, score = 100
            //   66894daa             | mov                 word ptr [ebp - 0x56], cx
            //   ba25000000           | mov                 edx, 0x25
            //   668955ac             | mov                 word ptr [ebp - 0x54], dx
            //   b832000000           | mov                 eax, 0x32
            //   668945ae             | mov                 word ptr [ebp - 0x52], ax
            //   b92e000000           | mov                 ecx, 0x2e

        $sequence_18 = { 66890a 8d85dcfcffff 50 e8???????? 83c404 e8???????? }
            // n = 6, score = 100
            //   66890a               | mov                 word ptr [edx], cx
            //   8d85dcfcffff         | lea                 eax, [ebp - 0x324]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e8????????           |                     

        $sequence_19 = { 03c1 8845ff 8b550c 0355f8 0fb602 0fb64dff }
            // n = 6, score = 100
            //   03c1                 | add                 eax, ecx
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   0355f8               | add                 edx, dword ptr [ebp - 8]
            //   0fb602               | movzx               eax, byte ptr [edx]
            //   0fb64dff             | movzx               ecx, byte ptr [ebp - 1]

        $sequence_20 = { 0fb7940de0fcffff 85d2 7505 e9???????? }
            // n = 4, score = 100
            //   0fb7940de0fcffff     | movzx               edx, word ptr [ebp + ecx - 0x320]
            //   85d2                 | test                edx, edx
            //   7505                 | jne                 7
            //   e9????????           |                     

        $sequence_21 = { 72f1 33c0 5d c3 8b04c544b40110 }
            // n = 5, score = 100
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c544b40110       | mov                 eax, dword ptr [eax*8 + 0x1001b444]

        $sequence_22 = { 6a00 8d55dc 52 e8???????? 83c408 898554ffffff }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   898554ffffff         | mov                 dword ptr [ebp - 0xac], eax

        $sequence_23 = { 8d95d4faffff 52 e8???????? 33c0 }
            // n = 4, score = 100
            //   8d95d4faffff         | lea                 edx, [ebp - 0x52c]
            //   52                   | push                edx
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 1018880
}