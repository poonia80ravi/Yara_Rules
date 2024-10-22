rule win_darkme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.darkme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkme"
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
        $sequence_0 = { c745a800000000 8d4dcc ff15???????? c745fc05000000 8b4d08 51 }
            // n = 6, score = 100
            //   c745a800000000       | mov                 dword ptr [ebp - 0x58], 0
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   ff15????????         |                     
            //   c745fc05000000       | mov                 dword ptr [ebp - 4], 5
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx

        $sequence_1 = { 8b35???????? bb01000000 8945b0 8bfb }
            // n = 4, score = 100
            //   8b35????????         |                     
            //   bb01000000           | mov                 ebx, 1
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8bfb                 | mov                 edi, ebx

        $sequence_2 = { 8d4d9c 51 8d955cffffff 52 }
            // n = 4, score = 100
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   51                   | push                ecx
            //   8d955cffffff         | lea                 edx, [ebp - 0xa4]
            //   52                   | push                edx

        $sequence_3 = { 50 e8???????? c745fc03000000 6aff ff15???????? c745fc04000000 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   c745fc03000000       | mov                 dword ptr [ebp - 4], 3
            //   6aff                 | push                -1
            //   ff15????????         |                     
            //   c745fc04000000       | mov                 dword ptr [ebp - 4], 4

        $sequence_4 = { 8bd0 8d4de8 ff15???????? 6a00 6880000000 }
            // n = 5, score = 100
            //   8bd0                 | mov                 edx, eax
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6880000000           | push                0x80

        $sequence_5 = { ff15???????? 8b45b8 50 8d4dc8 51 ff15???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   50                   | push                eax
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_6 = { 8b11 8b857cffffff 50 ff521c dbe2 898578ffffff 83bd78ffffff00 }
            // n = 7, score = 100
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b857cffffff         | mov                 eax, dword ptr [ebp - 0x84]
            //   50                   | push                eax
            //   ff521c               | call                dword ptr [edx + 0x1c]
            //   dbe2                 | fnclex              
            //   898578ffffff         | mov                 dword ptr [ebp - 0x88], eax
            //   83bd78ffffff00       | cmp                 dword ptr [ebp - 0x88], 0

        $sequence_7 = { 898574ffffff 83bd74ffffff00 7d23 6a2c 68???????? 8b8d78ffffff }
            // n = 6, score = 100
            //   898574ffffff         | mov                 dword ptr [ebp - 0x8c], eax
            //   83bd74ffffff00       | cmp                 dword ptr [ebp - 0x8c], 0
            //   7d23                 | jge                 0x25
            //   6a2c                 | push                0x2c
            //   68????????           |                     
            //   8b8d78ffffff         | mov                 ecx, dword ptr [ebp - 0x88]

        $sequence_8 = { 68???????? e8???????? 8b1d???????? 8bd0 8d8dc8fcffff ffd3 68???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   8b1d????????         |                     
            //   8bd0                 | mov                 edx, eax
            //   8d8dc8fcffff         | lea                 ecx, [ebp - 0x338]
            //   ffd3                 | call                ebx
            //   68????????           |                     

        $sequence_9 = { 894dc4 c745bc09000000 b810000000 e8???????? 8bd4 8b458c 8902 }
            // n = 7, score = 100
            //   894dc4               | mov                 dword ptr [ebp - 0x3c], ecx
            //   c745bc09000000       | mov                 dword ptr [ebp - 0x44], 9
            //   b810000000           | mov                 eax, 0x10
            //   e8????????           |                     
            //   8bd4                 | mov                 edx, esp
            //   8b458c               | mov                 eax, dword ptr [ebp - 0x74]
            //   8902                 | mov                 dword ptr [edx], eax

    condition:
        7 of them and filesize < 1515520
}