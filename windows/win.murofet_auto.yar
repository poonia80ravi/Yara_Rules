rule win_murofet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.murofet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murofet"
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
        $sequence_0 = { e8???????? 3c02 72e5 e8???????? a2???????? }
            // n = 5, score = 300
            //   e8????????           |                     
            //   3c02                 | cmp                 al, 2
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     
            //   a2????????           |                     

        $sequence_1 = { 32c0 eb43 be30750000 56 6a04 }
            // n = 5, score = 300
            //   32c0                 | xor                 al, al
            //   eb43                 | jmp                 0x45
            //   be30750000           | mov                 esi, 0x7530
            //   56                   | push                esi
            //   6a04                 | push                4

        $sequence_2 = { ff15???????? c6443eff00 83f8ff 7509 56 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0
            //   83f8ff               | cmp                 eax, -1
            //   7509                 | jne                 0xb
            //   56                   | push                esi

        $sequence_3 = { fec2 8816 e8???????? 0fb6c0 99 }
            // n = 5, score = 300
            //   fec2                 | inc                 dl
            //   8816                 | mov                 byte ptr [esi], dl
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   99                   | cdq                 

        $sequence_4 = { 84c0 7510 e8???????? 3c04 73ce b002 }
            // n = 6, score = 300
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2

        $sequence_5 = { eb43 be30750000 56 6a04 }
            // n = 4, score = 300
            //   eb43                 | jmp                 0x45
            //   be30750000           | mov                 esi, 0x7530
            //   56                   | push                esi
            //   6a04                 | push                4

        $sequence_6 = { fec2 8816 e8???????? 0fb6c0 99 f7ff }
            // n = 6, score = 300
            //   fec2                 | inc                 dl
            //   8816                 | mov                 byte ptr [esi], dl
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi

        $sequence_7 = { e8???????? a2???????? 84c0 7510 e8???????? }
            // n = 5, score = 300
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     

        $sequence_8 = { 7420 6a00 6880000000 6a01 6a00 }
            // n = 5, score = 300
            //   7420                 | je                  0x22
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_9 = { 8d4624 55 50 ff15???????? 83c40c }
            // n = 5, score = 300
            //   8d4624               | lea                 eax, [esi + 0x24]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc

    condition:
        7 of them and filesize < 622592
}