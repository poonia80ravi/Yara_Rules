rule win_mirage_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mirage."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mirage"
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
        $sequence_0 = { 285dff 8b864c010000 8a4dff 880c18 43 }
            // n = 5, score = 200
            // 
            //   8b864c010000         | mov                 eax, dword ptr [esi + 0x14c]
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   880c18               | mov                 byte ptr [eax + ebx], cl
            //   43                   | inc                 ebx

        $sequence_1 = { 8d45f4 50 53 68???????? c745f804010000 ff75fc ff15???????? }
            // n = 7, score = 200
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   68????????           |                     
            //   c745f804010000       | mov                 dword ptr [ebp - 8], 0x104
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     

        $sequence_2 = { 83c41c 8935???????? 8ac3 5f 5e }
            // n = 5, score = 200
            //   83c41c               | add                 esp, 0x1c
            //   8935????????         |                     
            //   8ac3                 | mov                 al, bl
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_3 = { 8dbd7dfdffff 889d7cfdffff f3ab 66ab aa 8d8580feffff 6804010000 }
            // n = 7, score = 200
            //   8dbd7dfdffff         | lea                 edi, [ebp - 0x283]
            //   889d7cfdffff         | mov                 byte ptr [ebp - 0x284], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d8580feffff         | lea                 eax, [ebp - 0x180]
            //   6804010000           | push                0x104

        $sequence_4 = { 56 53 50 a3???????? e8???????? 56 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   a3????????           |                     
            //   e8????????           |                     
            //   56                   | push                esi

        $sequence_5 = { 8d85bcbbffff 53 50 e8???????? }
            // n = 4, score = 200
            //   8d85bcbbffff         | lea                 eax, [ebp - 0x4444]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { e8???????? 8945e0 ffd6 2bc3 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   ffd6                 | call                esi
            //   2bc3                 | sub                 eax, ebx

        $sequence_7 = { 50 e8???????? 59 898748010000 5f }
            // n = 5, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   898748010000         | mov                 dword ptr [edi + 0x148], eax
            //   5f                   | pop                 edi

        $sequence_8 = { 68???????? 6801000080 ff15???????? 85c0 7556 }
            // n = 5, score = 200
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7556                 | jne                 0x58

        $sequence_9 = { c3 b8???????? e8???????? b840840000 }
            // n = 4, score = 200
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   b840840000           | mov                 eax, 0x8440

        $sequence_10 = { 57 33db b9ff010000 33c0 8dbdf2f7ffff 66899df0f7ffff }
            // n = 6, score = 100
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   b9ff010000           | mov                 ecx, 0x1ff
            //   33c0                 | xor                 eax, eax
            //   8dbdf2f7ffff         | lea                 edi, [ebp - 0x80e]
            //   66899df0f7ffff       | mov                 word ptr [ebp - 0x810], bx

        $sequence_11 = { ff75fc e8???????? ff75fc e8???????? 83c410 8d851cfdffff }
            // n = 6, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d851cfdffff         | lea                 eax, [ebp - 0x2e4]

        $sequence_12 = { 68???????? 8d85f0f7ffff 68???????? 50 e8???????? a1???????? 83c410 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d85f0f7ffff         | lea                 eax, [ebp - 0x810]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   a1????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_13 = { 83c424 3bc3 753f 6a1f 33c0 }
            // n = 5, score = 100
            //   83c424               | add                 esp, 0x24
            //   3bc3                 | cmp                 eax, ebx
            //   753f                 | jne                 0x41
            //   6a1f                 | push                0x1f
            //   33c0                 | xor                 eax, eax

        $sequence_14 = { 8dbd0df1ffff 889d0cf1ffff f3ab 66ab 6a20 56 }
            // n = 6, score = 100
            //   8dbd0df1ffff         | lea                 edi, [ebp - 0xef3]
            //   889d0cf1ffff         | mov                 byte ptr [ebp - 0xef4], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   6a20                 | push                0x20
            //   56                   | push                esi

        $sequence_15 = { 85c0 a3???????? 0f848f000000 68???????? 56 }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   a3????????           |                     
            //   0f848f000000         | je                  0x95
            //   68????????           |                     
            //   56                   | push                esi

    condition:
        7 of them and filesize < 1695744
}