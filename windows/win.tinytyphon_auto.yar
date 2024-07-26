rule win_tinytyphon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.tinytyphon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinytyphon"
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
        $sequence_0 = { 0fb65113 c1e218 0bc2 8b4d08 894168 }
            // n = 5, score = 200
            //   0fb65113             | movzx               edx, byte ptr [ecx + 0x13]
            //   c1e218               | shl                 edx, 0x18
            //   0bc2                 | or                  eax, edx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   894168               | mov                 dword ptr [ecx + 0x68], eax

        $sequence_1 = { 6a00 ff15???????? 8945e8 837de800 7406 837de8ff 7517 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   7406                 | je                  8
            //   837de8ff             | cmp                 dword ptr [ebp - 0x18], -1
            //   7517                 | jne                 0x19

        $sequence_2 = { c745c440144000 c745c844144000 c745cc48144000 c745d04c144000 }
            // n = 4, score = 200
            //   c745c440144000       | mov                 dword ptr [ebp - 0x3c], 0x401440
            //   c745c844144000       | mov                 dword ptr [ebp - 0x38], 0x401444
            //   c745cc48144000       | mov                 dword ptr [ebp - 0x34], 0x401448
            //   c745d04c144000       | mov                 dword ptr [ebp - 0x30], 0x40144c

        $sequence_3 = { 8b4df4 0fb65137 c1e218 0bc2 }
            // n = 4, score = 200
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   0fb65137             | movzx               edx, byte ptr [ecx + 0x37]
            //   c1e218               | shl                 edx, 0x18
            //   0bc2                 | or                  eax, edx

        $sequence_4 = { 8b55dc 0355e0 8955dc 8b45dc 3345e0 3345f8 }
            // n = 6, score = 200
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   0355e0               | add                 edx, dword ptr [ebp - 0x20]
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   3345e0               | xor                 eax, dword ptr [ebp - 0x20]
            //   3345f8               | xor                 eax, dword ptr [ebp - 8]

        $sequence_5 = { ff15???????? 89855cffffff 83bd5cffffff00 7524 8b9554ffffff 52 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   89855cffffff         | mov                 dword ptr [ebp - 0xa4], eax
            //   83bd5cffffff00       | cmp                 dword ptr [ebp - 0xa4], 0
            //   7524                 | jne                 0x26
            //   8b9554ffffff         | mov                 edx, dword ptr [ebp - 0xac]
            //   52                   | push                edx

        $sequence_6 = { 8945f8 8b4df4 0fb65124 8b45f4 }
            // n = 4, score = 200
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   0fb65124             | movzx               edx, byte ptr [ecx + 0x24]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_7 = { b801000000 eb28 837d0c00 7420 6aff 8b55f0 }
            // n = 6, score = 200
            //   b801000000           | mov                 eax, 1
            //   eb28                 | jmp                 0x2a
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7420                 | je                  0x22
            //   6aff                 | push                -1
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]

        $sequence_8 = { 0355dc 8955e4 8b45e0 f7d0 0b45e4 3345dc }
            // n = 6, score = 200
            //   0355dc               | add                 edx, dword ptr [ebp - 0x24]
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   f7d0                 | not                 eax
            //   0b45e4               | or                  eax, dword ptr [ebp - 0x1c]
            //   3345dc               | xor                 eax, dword ptr [ebp - 0x24]

        $sequence_9 = { 8d9411937198fd 8955e0 8b45e0 c1e00c 8b4de0 c1e914 0bc1 }
            // n = 7, score = 200
            //   8d9411937198fd       | lea                 edx, [ecx + edx - 0x2678e6d]
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   c1e00c               | shl                 eax, 0xc
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   c1e914               | shr                 ecx, 0x14
            //   0bc1                 | or                  eax, ecx

    condition:
        7 of them and filesize < 90112
}