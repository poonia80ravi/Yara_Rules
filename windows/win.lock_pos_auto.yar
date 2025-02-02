rule win_lock_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lock_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lock_pos"
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
        $sequence_0 = { 55 8bec 8b4508 8b0d???????? 8b0481 }
            // n = 5, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0d????????         |                     
            //   8b0481               | mov                 eax, dword ptr [ecx + eax*4]

        $sequence_1 = { 55 8bec 837d0800 7704 33c0 }
            // n = 5, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7704                 | ja                  6
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 6a00 6a23 6a00 ff15???????? 8d8df8fdffff }
            // n = 5, score = 300
            //   6a00                 | push                0
            //   6a23                 | push                0x23
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8d8df8fdffff         | lea                 ecx, [ebp - 0x208]

        $sequence_3 = { 8d85f8fdffff 50 6a00 6a00 6a23 }
            // n = 5, score = 300
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a23                 | push                0x23

        $sequence_4 = { 55 8bec 81eca4040000 56 }
            // n = 4, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81eca4040000         | sub                 esp, 0x4a4
            //   56                   | push                esi

        $sequence_5 = { 8b55f0 8b4508 03421c 0fb74de4 8b5508 031488 }
            // n = 6, score = 200
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   03421c               | add                 eax, dword ptr [edx + 0x1c]
            //   0fb74de4             | movzx               ecx, word ptr [ebp - 0x1c]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   031488               | add                 edx, dword ptr [eax + ecx*4]

        $sequence_6 = { ff15???????? 8945fc eb2b 8b8588fbffff 50 e8???????? 83c404 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   eb2b                 | jmp                 0x2d
            //   8b8588fbffff         | mov                 eax, dword ptr [ebp - 0x478]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_7 = { 81c100020000 894df8 817df80000a000 771e }
            // n = 4, score = 200
            //   81c100020000         | add                 ecx, 0x200
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   817df80000a000       | cmp                 dword ptr [ebp - 8], 0xa00000
            //   771e                 | ja                  0x20

        $sequence_8 = { ff7508 8bce e8???????? 83c40c 5b }
            // n = 5, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   5b                   | pop                 ebx

        $sequence_9 = { 8945f8 8b4dfc 83c102 894dfc ebe2 8b45f8 8be5 }
            // n = 7, score = 200
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c102               | add                 ecx, 2
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   ebe2                 | jmp                 0xffffffe4
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8be5                 | mov                 esp, ebp

        $sequence_10 = { 8945e8 eb96 8b4df8 81c180000000 894ddc }
            // n = 5, score = 200
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   eb96                 | jmp                 0xffffff98
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   81c180000000         | add                 ecx, 0x80
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx

        $sequence_11 = { 33f6 8975f8 3935???????? 0f868d000000 53 }
            // n = 5, score = 200
            //   33f6                 | xor                 esi, esi
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   3935????????         |                     
            //   0f868d000000         | jbe                 0x93
            //   53                   | push                ebx

        $sequence_12 = { 8b4508 5f 59 9d }
            // n = 4, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   5f                   | pop                 edi
            //   59                   | pop                 ecx
            //   9d                   | popfd               

    condition:
        7 of them and filesize < 319488
}