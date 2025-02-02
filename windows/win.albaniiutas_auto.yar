rule win_albaniiutas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.albaniiutas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.albaniiutas"
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
        $sequence_0 = { 83e801 0f859b010000 c745e0e87c0110 8b4508 }
            // n = 4, score = 100
            //   83e801               | sub                 eax, 1
            //   0f859b010000         | jne                 0x1a1
            //   c745e0e87c0110       | mov                 dword ptr [ebp - 0x20], 0x10017ce8
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_1 = { 53 8b5d08 33c9 57 33c0 8d3c9dbcdd0210 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax
            //   8d3c9dbcdd0210       | lea                 edi, [ebx*4 + 0x1002ddbc]

        $sequence_2 = { 680c800000 ff75f8 ff15???????? 85c0 744e 6a00 }
            // n = 6, score = 100
            //   680c800000           | push                0x800c
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   744e                 | je                  0x50
            //   6a00                 | push                0

        $sequence_3 = { 331485c01c0110 0fb6c3 331485c0280110 33560c 8bca }
            // n = 5, score = 100
            //   331485c01c0110       | xor                 edx, dword ptr [eax*4 + 0x10011cc0]
            //   0fb6c3               | movzx               eax, bl
            //   331485c0280110       | xor                 edx, dword ptr [eax*4 + 0x100128c0]
            //   33560c               | xor                 edx, dword ptr [esi + 0xc]
            //   8bca                 | mov                 ecx, edx

        $sequence_4 = { e9???????? 8b4508 c74018d81a0110 c74104513f0000 e9???????? 83fe10 732d }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c74018d81a0110       | mov                 dword ptr [eax + 0x18], 0x10011ad8
            //   c74104513f0000       | mov                 dword ptr [ecx + 4], 0x3f51
            //   e9????????           |                     
            //   83fe10               | cmp                 esi, 0x10
            //   732d                 | jae                 0x2f

        $sequence_5 = { 8bde c1fb06 83e03f 6bd030 895de4 8b049d90df0210 }
            // n = 6, score = 100
            //   8bde                 | mov                 ebx, esi
            //   c1fb06               | sar                 ebx, 6
            //   83e03f               | and                 eax, 0x3f
            //   6bd030               | imul                edx, eax, 0x30
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   8b049d90df0210       | mov                 eax, dword ptr [ebx*4 + 0x1002df90]

        $sequence_6 = { c74018c41b0110 c74104513f0000 e9???????? 8d8134050000 }
            // n = 4, score = 100
            //   c74018c41b0110       | mov                 dword ptr [eax + 0x18], 0x10011bc4
            //   c74104513f0000       | mov                 dword ptr [ecx + 4], 0x3f51
            //   e9????????           |                     
            //   8d8134050000         | lea                 eax, [ecx + 0x534]

        $sequence_7 = { c745e802000000 c745ec07000000 c745f000000000 c745f400000000 c745f801000000 c745fcb80b0000 }
            // n = 6, score = 100
            //   c745e802000000       | mov                 dword ptr [ebp - 0x18], 2
            //   c745ec07000000       | mov                 dword ptr [ebp - 0x14], 7
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   c745fcb80b0000       | mov                 dword ptr [ebp - 4], 0xbb8

        $sequence_8 = { 8bcf 83e03f c1f906 6bf030 03348d90df0210 837e18ff }
            // n = 6, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   83e03f               | and                 eax, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bf030               | imul                esi, eax, 0x30
            //   03348d90df0210       | add                 esi, dword ptr [ecx*4 + 0x1002df90]
            //   837e18ff             | cmp                 dword ptr [esi + 0x18], -1

        $sequence_9 = { be???????? 8b02 8d7a04 f3a5 8bca }
            // n = 5, score = 100
            //   be????????           |                     
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8d7a04               | lea                 edi, [edx + 4]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx

    condition:
        7 of them and filesize < 566272
}