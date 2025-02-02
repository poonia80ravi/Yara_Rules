rule win_payloadbin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.payloadbin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.payloadbin"
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
        $sequence_0 = { c0e3c5 4881842420000000a514c368 4153 68d8769078 415b 415b }
            // n = 6, score = 100
            //   c0e3c5               | lea                 eax, [esp + 0xa0]
            //   4881842420000000a514c368     | dec    eax
            //   4153                 | mov                 edx, ebp
            //   68d8769078           | mov                 ecx, 0xf43a495d
            //   415b                 | inc                 ecx
            //   415b                 | cmp                 eax, edi

        $sequence_1 = { 49d3f8 41d2dd 498bf9 4180d166 443bc5 4181c46e02a3ee 8bea }
            // n = 7, score = 100
            //   49d3f8               | shl                 eax, 2
            //   41d2dd               | inc                 cx
            //   498bf9               | btr                 eax, esi
            //   4180d166             | inc                 cx
            //   443bc5               | sbb                 eax, 0xd22b7f55
            //   4181c46e02a3ee       | cmc                 
            //   8bea                 | dec                 ecx

        $sequence_2 = { 5f 66be1b1e 5e 5d 8afe 4863dd 5b }
            // n = 7, score = 100
            //   5f                   | movsx               esp, bl
            //   66be1b1e             | dec                 esp
            //   5e                   | movzx               esp, bx
            //   5d                   | inc                 ecx
            //   8afe                 | inc                 ah
            //   4863dd               | dec                 esp
            //   5b                   | mov                 esp, edi

        $sequence_3 = { 4d0f45ef 4533c9 e8???????? 488b7c2438 4c8d4668 413bc7 }
            // n = 6, score = 100
            //   4d0f45ef             | arpl                bp, ax
            //   4533c9               | dec                 ebp
            //   e8????????           |                     
            //   488b7c2438           | bts                 ebx, eax
            //   4c8d4668             | mov                 eax, ecx
            //   413bc7               | inc                 ecx

        $sequence_4 = { 0f8229000000 4881bc2418000000572afb3c 6846569974 681a2ee31b 687a66130b 488b542438 }
            // n = 6, score = 100
            //   0f8229000000         | movzx               edx, dl
            //   4881bc2418000000572afb3c     | dec    ebp
            //   6846569974           | arpl                bp, dx
            //   681a2ee31b           | inc                 cx
            //   687a66130b           | bswap               edx
            //   488b542438           | dec                 esp

        $sequence_5 = { 57 418ad1 f8 4154 e9???????? 4155 }
            // n = 6, score = 100
            //   57                   | lea                 eax, [ecx + ebx*2 - 6]
            //   418ad1               | inc                 edx
            //   f8                   | test                byte ptr [esp + edi - 0x7b020f48], 0x12
            //   4154                 | dec                 ecx
            //   e9????????           |                     
            //   4155                 | mov                 eax, edi

        $sequence_6 = { 488b6c2438 0fabc6 48c1f63f 488b742440 9f 488bc7 488b7c2448 }
            // n = 7, score = 100
            //   488b6c2438           | shld                ebx, esp, 0xea
            //   0fabc6               | inc                 ebp
            //   48c1f63f             | sub                 ebp, ebp
            //   488b742440           | dec                 eax
            //   9f                   | mov                 ebx, ecx
            //   488bc7               | inc                 eax
            //   488b7c2448           | sar                 bh, cl

        $sequence_7 = { 9d e8???????? 9d 488d642408 e8???????? 687a79eb21 58 }
            // n = 7, score = 100
            //   9d                   | push                ebp
            //   e8????????           |                     
            //   9d                   | add                 ebp, 0x9403bd4
            //   488d642408           | inc                 eax
            //   e8????????           |                     
            //   687a79eb21           | rcl                 ch, 0x63
            //   58                   | xor                 dword ptr [esp], ebx

        $sequence_8 = { 490f44eb 40b58f 4150 660fcd 66410fbee9 52 41b001 }
            // n = 7, score = 100
            //   490f44eb             | inc                 ecx
            //   40b58f               | sal                 cl, 0xc1
            //   4150                 | inc                 ecx
            //   660fcd               | cmp                 bh, 2
            //   66410fbee9           | neg                 ebx
            //   52                   | rol                 ebx, 1
            //   41b001               | dec                 esp

        $sequence_9 = { 0fbaff53 400afd 418b3b 4133f8 f7df c1cf02 f7d7 }
            // n = 7, score = 100
            //   0fbaff53             | xchg                eax, edi
            //   400afd               | jno                 0x21
            //   418b3b               | fsubp               st(4)
            //   4133f8               | sti                 
            //   f7df                 | sbb                 dword ptr [esi], esp
            //   c1cf02               | fisubr              dword ptr [eax - 0x132619c1]
            //   f7d7                 | xchg                eax, edi

    condition:
        7 of them and filesize < 3761152
}