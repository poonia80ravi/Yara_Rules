rule win_unidentified_075_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_075."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_075"
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
        $sequence_0 = { c645d664 c645d76f c645d877 c645d973 c645da20 c645db4e c645dc54 }
            // n = 7, score = 200
            //   c645d664             | mov                 byte ptr [ebp - 0x2a], 0x64
            //   c645d76f             | mov                 byte ptr [ebp - 0x29], 0x6f
            //   c645d877             | mov                 byte ptr [ebp - 0x28], 0x77
            //   c645d973             | mov                 byte ptr [ebp - 0x27], 0x73
            //   c645da20             | mov                 byte ptr [ebp - 0x26], 0x20
            //   c645db4e             | mov                 byte ptr [ebp - 0x25], 0x4e
            //   c645dc54             | mov                 byte ptr [ebp - 0x24], 0x54

        $sequence_1 = { 8b45fc 83c03c 50 e8???????? 83c404 }
            // n = 5, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c03c               | add                 eax, 0x3c
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_2 = { b972000000 66894dc0 ba6f000000 668955c2 b866000000 668945c4 b969000000 }
            // n = 7, score = 200
            //   b972000000           | mov                 ecx, 0x72
            //   66894dc0             | mov                 word ptr [ebp - 0x40], cx
            //   ba6f000000           | mov                 edx, 0x6f
            //   668955c2             | mov                 word ptr [ebp - 0x3e], dx
            //   b866000000           | mov                 eax, 0x66
            //   668945c4             | mov                 word ptr [ebp - 0x3c], ax
            //   b969000000           | mov                 ecx, 0x69

        $sequence_3 = { 894dfc 8b55f4 8b02 8945d0 }
            // n = 4, score = 200
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax

        $sequence_4 = { 668945de b974000000 66894de0 ba50000000 668955e2 b872000000 668945e4 }
            // n = 7, score = 200
            //   668945de             | mov                 word ptr [ebp - 0x22], ax
            //   b974000000           | mov                 ecx, 0x74
            //   66894de0             | mov                 word ptr [ebp - 0x20], cx
            //   ba50000000           | mov                 edx, 0x50
            //   668955e2             | mov                 word ptr [ebp - 0x1e], dx
            //   b872000000           | mov                 eax, 0x72
            //   668945e4             | mov                 word ptr [ebp - 0x1c], ax

        $sequence_5 = { 51 8d95a4e2ffff 52 e8???????? }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8d95a4e2ffff         | lea                 edx, [ebp - 0x1d5c]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_6 = { 33c0 668945d0 8d4dd4 51 }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   668945d0             | mov                 word ptr [ebp - 0x30], ax
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   51                   | push                ecx

        $sequence_7 = { 8b4df0 898d54ffffff c78550ffffff00000000 6a00 6a00 }
            // n = 5, score = 200
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   898d54ffffff         | mov                 dword ptr [ebp - 0xac], ecx
            //   c78550ffffff00000000     | mov    dword ptr [ebp - 0xb0], 0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_8 = { 668945dc 837df800 7408 8b4df8 894df4 }
            // n = 5, score = 200
            //   668945dc             | mov                 word ptr [ebp - 0x24], ax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7408                 | je                  0xa
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_9 = { 81eca4000000 894dfc c745f400000000 c745f800000000 }
            // n = 4, score = 200
            //   81eca4000000         | sub                 esp, 0xa4
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

    condition:
        7 of them and filesize < 393216
}