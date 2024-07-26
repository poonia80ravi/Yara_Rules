rule win_idkey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.idkey"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { b121 e8???????? 8d956cfdffff 8d8548fdffff e8???????? b069 e8???????? }
            // n = 7, score = 100
            //   b121                 | mov                 cl, 0x21
            //   e8????????           |                     
            //   8d956cfdffff         | lea                 edx, [ebp - 0x294]
            //   8d8548fdffff         | lea                 eax, [ebp - 0x2b8]
            //   e8????????           |                     
            //   b069                 | mov                 al, 0x69
            //   e8????????           |                     

        $sequence_1 = { e8???????? b06e e8???????? 8bd0 8d85e4feffff }
            // n = 5, score = 100
            //   e8????????           |                     
            //   b06e                 | mov                 al, 0x6e
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]

        $sequence_2 = { b121 e8???????? 8d956cfdffff 8d8548fdffff e8???????? b069 }
            // n = 6, score = 100
            //   b121                 | mov                 cl, 0x21
            //   e8????????           |                     
            //   8d956cfdffff         | lea                 edx, [ebp - 0x294]
            //   8d8548fdffff         | lea                 eax, [ebp - 0x2b8]
            //   e8????????           |                     
            //   b069                 | mov                 al, 0x69

        $sequence_3 = { 8ac3 80b828298e0000 7576 833d????????00 }
            // n = 4, score = 100
            //   8ac3                 | mov                 al, bl
            //   80b828298e0000       | cmp                 byte ptr [eax + 0x8e2928], 0
            //   7576                 | jne                 0x78
            //   833d????????00       |                     

        $sequence_4 = { 8d85a0fbffff ba1a000000 e8???????? 8b95a0fbffff 8bc6 8b08 }
            // n = 6, score = 100
            //   8d85a0fbffff         | lea                 eax, [ebp - 0x460]
            //   ba1a000000           | mov                 edx, 0x1a
            //   e8????????           |                     
            //   8b95a0fbffff         | mov                 edx, dword ptr [ebp - 0x460]
            //   8bc6                 | mov                 eax, esi
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_5 = { c60001 8d55ec 8d45d8 b105 e8???????? 8d55d8 8d45d0 }
            // n = 7, score = 100
            //   c60001               | mov                 byte ptr [eax], 1
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   b105                 | mov                 cl, 5
            //   e8????????           |                     
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   8d45d0               | lea                 eax, [ebp - 0x30]

        $sequence_6 = { dbac53bd2e8900 dec9 c1e804 7461 8d0480 dbac43532f8900 }
            // n = 6, score = 100
            //   dbac53bd2e8900       | fld                 xword ptr [ebx + edx*2 + 0x892ebd]
            //   dec9                 | fmulp               st(1)
            //   c1e804               | shr                 eax, 4
            //   7461                 | je                  0x63
            //   8d0480               | lea                 eax, [eax + eax*4]
            //   dbac43532f8900       | fld                 xword ptr [ebx + eax*2 + 0x892f53]

        $sequence_7 = { e8???????? b028 e8???????? 8bd0 8d45ec 885001 c60001 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   b028                 | mov                 al, 0x28
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   885001               | mov                 byte ptr [eax + 1], dl
            //   c60001               | mov                 byte ptr [eax], 1

        $sequence_8 = { 8d8534feffff b11b e8???????? 8d9534feffff }
            // n = 4, score = 100
            //   8d8534feffff         | lea                 eax, [ebp - 0x1cc]
            //   b11b                 | mov                 cl, 0x1b
            //   e8????????           |                     
            //   8d9534feffff         | lea                 edx, [ebp - 0x1cc]

        $sequence_9 = { c60001 8d55ec 8d45c8 b107 e8???????? 8d55c8 }
            // n = 6, score = 100
            //   c60001               | mov                 byte ptr [eax], 1
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   b107                 | mov                 cl, 7
            //   e8????????           |                     
            //   8d55c8               | lea                 edx, [ebp - 0x38]

    condition:
        7 of them and filesize < 811008
}