rule win_romeos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.romeos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romeos"
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
        $sequence_0 = { e8???????? 85c0 0f850d010000 33db 6a16 8d4c244c 6800200000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f850d010000         | jne                 0x113
            //   33db                 | xor                 ebx, ebx
            //   6a16                 | push                0x16
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   6800200000           | push                0x2000

        $sequence_1 = { 85db 751d 807c244802 0f85e0000000 8d542414 }
            // n = 5, score = 400
            //   85db                 | test                ebx, ebx
            //   751d                 | jne                 0x1f
            //   807c244802           | cmp                 byte ptr [esp + 0x48], 2
            //   0f85e0000000         | jne                 0xe6
            //   8d542414             | lea                 edx, [esp + 0x14]

        $sequence_2 = { 8d44241b 6a01 50 57 8bce e8???????? }
            // n = 6, score = 400
            //   8d44241b             | lea                 eax, [esp + 0x1b]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_3 = { 57 b9ff070000 33c0 8d7c2449 c644244800 6a16 f3ab }
            // n = 7, score = 400
            //   57                   | push                edi
            //   b9ff070000           | mov                 ecx, 0x7ff
            //   33c0                 | xor                 eax, eax
            //   8d7c2449             | lea                 edi, [esp + 0x49]
            //   c644244800           | mov                 byte ptr [esp + 0x48], 0
            //   6a16                 | push                0x16
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_4 = { 807c24480e 7406 43 83fb08 7cb6 e8???????? }
            // n = 6, score = 400
            //   807c24480e           | cmp                 byte ptr [esp + 0x48], 0xe
            //   7406                 | je                  8
            //   43                   | inc                 ebx
            //   83fb08               | cmp                 ebx, 8
            //   7cb6                 | jl                  0xffffffb8
            //   e8????????           |                     

        $sequence_5 = { 43 3bdd 7cf2 8b542414 6a16 }
            // n = 5, score = 400
            //   43                   | inc                 ebx
            //   3bdd                 | cmp                 ebx, ebp
            //   7cf2                 | jl                  0xfffffff4
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   6a16                 | push                0x16

        $sequence_6 = { 7522 50 6a16 8d4c2420 55 51 57 }
            // n = 7, score = 400
            //   7522                 | jne                 0x24
            //   50                   | push                eax
            //   6a16                 | push                0x16
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   55                   | push                ebp
            //   51                   | push                ecx
            //   57                   | push                edi

        $sequence_7 = { b161 884c2414 8b5c2414 880e 81e3ff000000 46 53 }
            // n = 7, score = 400
            //   b161                 | mov                 cl, 0x61
            //   884c2414             | mov                 byte ptr [esp + 0x14], cl
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   880e                 | mov                 byte ptr [esi], cl
            //   81e3ff000000         | and                 ebx, 0xff
            //   46                   | inc                 esi
            //   53                   | push                ebx

        $sequence_8 = { 8b542470 52 6a08 ff15???????? 8be8 b988000000 33c0 }
            // n = 7, score = 200
            //   8b542470             | mov                 edx, dword ptr [esp + 0x70]
            //   52                   | push                edx
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   8be8                 | mov                 ebp, eax
            //   b988000000           | mov                 ecx, 0x88
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 33c0 8a87781f0110 668b94867e0a0000 66d3e2 660996b8160000 83c103 898ebc160000 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8a87781f0110         | mov                 al, byte ptr [edi + 0x10011f78]
            //   668b94867e0a0000     | mov                 dx, word ptr [esi + eax*4 + 0xa7e]
            //   66d3e2               | shl                 dx, cl
            //   660996b8160000       | or                  word ptr [esi + 0x16b8], dx
            //   83c103               | add                 ecx, 3
            //   898ebc160000         | mov                 dword ptr [esi + 0x16bc], ecx

        $sequence_10 = { 68a0570110 55 a3???????? ffd6 6888570110 55 a3???????? }
            // n = 7, score = 200
            //   68a0570110           | push                0x100157a0
            //   55                   | push                ebp
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   6888570110           | push                0x10015788
            //   55                   | push                ebp
            //   a3????????           |                     

        $sequence_11 = { 7dea 8b1d???????? 6a01 ff15???????? }
            // n = 4, score = 200
            //   7dea                 | jge                 0xffffffec
            //   8b1d????????         |                     
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_12 = { 6685c9 7419 51 50 8bce e8???????? }
            // n = 6, score = 200
            //   6685c9               | test                cx, cx
            //   7419                 | je                  0x1b
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_13 = { 6802100000 68ffff0000 56 c744241800000100 ff15???????? 8b4c2420 }
            // n = 6, score = 200
            //   6802100000           | push                0x1002
            //   68ffff0000           | push                0xffff
            //   56                   | push                esi
            //   c744241800000100     | mov                 dword ptr [esp + 0x18], 0x10000
            //   ff15????????         |                     
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]

        $sequence_14 = { 56 a3???????? ffd7 68fc580110 56 a3???????? ffd7 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   a3????????           |                     
            //   ffd7                 | call                edi
            //   68fc580110           | push                0x100158fc
            //   56                   | push                esi
            //   a3????????           |                     
            //   ffd7                 | call                edi

        $sequence_15 = { 51 52 895c2424 aa ff15???????? }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   52                   | push                edx
            //   895c2424             | mov                 dword ptr [esp + 0x24], ebx
            //   aa                   | stosb               byte ptr es:[edi], al
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 294912
}