rule win_matryoshka_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.matryoshka_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matryoshka_rat"
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
        $sequence_0 = { b037 c3 b073 c3 }
            // n = 4, score = 400
            //   b037                 | mov                 al, 0x37
            //   c3                   | ret                 
            //   b073                 | mov                 al, 0x73
            //   c3                   | ret                 

        $sequence_1 = { b06f c3 b063 c3 }
            // n = 4, score = 400
            //   b06f                 | mov                 al, 0x6f
            //   c3                   | ret                 
            //   b063                 | mov                 al, 0x63
            //   c3                   | ret                 

        $sequence_2 = { 742a 33c0 488906 488bcd e8???????? }
            // n = 5, score = 200
            //   742a                 | je                  0x2c
            //   33c0                 | xor                 eax, eax
            //   488906               | dec                 eax
            //   488bcd               | mov                 dword ptr [esi], eax
            //   e8????????           |                     

        $sequence_3 = { 8b45fc ff75c8 894720 8b45f0 }
            // n = 4, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   894720               | mov                 dword ptr [edi + 0x20], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_4 = { 742b 448bc3 488bd5 488bcf }
            // n = 4, score = 200
            //   742b                 | mov                 ecx, eax
            //   448bc3               | je                  0x2c
            //   488bd5               | mov                 ecx, dword ptr [ebx + 0x38]
            //   488bcf               | lea                 eax, [ecx + edi]

        $sequence_5 = { 742b 4c8bc5 33d2 488bc8 }
            // n = 4, score = 200
            //   742b                 | dec                 eax
            //   4c8bc5               | mov                 ecx, edi
            //   33d2                 | cmp                 eax, ebx
            //   488bc8               | jne                 0x40

        $sequence_6 = { 8b45fc c1e810 0345fc 25ffff0000 }
            // n = 4, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c1e810               | shr                 eax, 0x10
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   25ffff0000           | and                 eax, 0xffff

        $sequence_7 = { 742b 85db 7527 488d0dbc540400 }
            // n = 4, score = 200
            //   742b                 | mov                 ecx, esi
            //   85db                 | dec                 eax
            //   7527                 | mov                 ecx, dword ptr [ebx]
            //   488d0dbc540400       | xor                 edx, edx

        $sequence_8 = { 8b45fc a3???????? 8d45fc 50 68???????? }
            // n = 5, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   a3????????           |                     
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_9 = { 8b45fc bb???????? a3???????? 8d45fc }
            // n = 4, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   bb????????           |                     
            //   a3????????           |                     
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_10 = { 8b45fc eb0d 8b45fc 8b550c }
            // n = 4, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   eb0d                 | jmp                 0xf
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_11 = { 742b 488bce e8???????? 488b0b }
            // n = 4, score = 200
            //   742b                 | mov                 edx, ebp
            //   488bce               | dec                 eax
            //   e8????????           |                     
            //   488b0b               | mov                 ecx, edi

        $sequence_12 = { 742a 8b4b38 8d0439 3b433c 7209 c7432400000300 eb51 }
            // n = 7, score = 200
            //   742a                 | je                  0x2c
            //   8b4b38               | xor                 eax, eax
            //   8d0439               | dec                 eax
            //   3b433c               | mov                 dword ptr [esi], eax
            //   7209                 | dec                 eax
            //   c7432400000300       | mov                 ecx, ebp
            //   eb51                 | dec                 eax

        $sequence_13 = { 8b45fc 8d8f44010000 898770010000 e8???????? e9???????? 5f }
            // n = 6, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8d8f44010000         | lea                 ecx, [edi + 0x144]
            //   898770010000         | mov                 dword ptr [edi + 0x170], eax
            //   e8????????           |                     
            //   e9????????           |                     
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 843776
}