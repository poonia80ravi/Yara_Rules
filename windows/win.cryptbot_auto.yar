rule win_cryptbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.cryptbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptbot"
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
        $sequence_0 = { 33c0 85ed 0f94c0 8be8 }
            // n = 4, score = 700
            //   33c0                 | xor                 eax, eax
            //   85ed                 | test                ebp, ebp
            //   0f94c0               | sete                al
            //   8be8                 | mov                 ebp, eax

        $sequence_1 = { e9???????? b944dc0000 e9???????? b964dc0000 e9???????? b95ddc0000 }
            // n = 6, score = 600
            //   e9????????           |                     
            //   b944dc0000           | mov                 ecx, 0xdc44
            //   e9????????           |                     
            //   b964dc0000           | mov                 ecx, 0xdc64
            //   e9????????           |                     
            //   b95ddc0000           | mov                 ecx, 0xdc5d

        $sequence_2 = { e8???????? 84c0 7514 b800000002 e9???????? }
            // n = 5, score = 600
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7514                 | jne                 0x16
            //   b800000002           | mov                 eax, 0x2000000
            //   e9????????           |                     

        $sequence_3 = { e8???????? 85c0 750e b9ca070200 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10
            //   b9ca070200           | mov                 ecx, 0x207ca

        $sequence_4 = { e9???????? b949dc0000 e9???????? b944dc0000 }
            // n = 4, score = 600
            //   e9????????           |                     
            //   b949dc0000           | mov                 ecx, 0xdc49
            //   e9????????           |                     
            //   b944dc0000           | mov                 ecx, 0xdc44

        $sequence_5 = { eb0c b99fed0000 e8???????? 8907 }
            // n = 4, score = 600
            //   eb0c                 | jmp                 0xe
            //   b99fed0000           | mov                 ecx, 0xed9f
            //   e8????????           |                     
            //   8907                 | mov                 dword ptr [edi], eax

        $sequence_6 = { 0f9cc0 eb02 32c0 84c0 }
            // n = 4, score = 600
            //   0f9cc0               | setl                al
            //   eb02                 | jmp                 4
            //   32c0                 | xor                 al, al
            //   84c0                 | test                al, al

        $sequence_7 = { 33c0 eb0a b917d90000 e8???????? }
            // n = 4, score = 600
            //   33c0                 | xor                 eax, eax
            //   eb0a                 | jmp                 0xc
            //   b917d90000           | mov                 ecx, 0xd917
            //   e8????????           |                     

        $sequence_8 = { 744e 0fb74802 83e103 3bcb }
            // n = 4, score = 400
            //   744e                 | je                  0x50
            //   0fb74802             | movzx               ecx, word ptr [eax + 2]
            //   83e103               | and                 ecx, 3
            //   3bcb                 | cmp                 ecx, ebx

        $sequence_9 = { 7403 034a04 ffb5ec010000 51 }
            // n = 4, score = 400
            //   7403                 | je                  5
            //   034a04               | add                 ecx, dword ptr [edx + 4]
            //   ffb5ec010000         | push                dword ptr [ebp + 0x1ec]
            //   51                   | push                ecx

        $sequence_10 = { 7518 8b542414 83c718 8bcd 13f0 56 }
            // n = 6, score = 400
            //   7518                 | jne                 0x1a
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   83c718               | add                 edi, 0x18
            //   8bcd                 | mov                 ecx, ebp
            //   13f0                 | adc                 esi, eax
            //   56                   | push                esi

        $sequence_11 = { 7419 8b542408 83fa01 7c10 0fbf4846 3bd1 7f08 }
            // n = 7, score = 400
            //   7419                 | je                  0x1b
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   83fa01               | cmp                 edx, 1
            //   7c10                 | jl                  0x12
            //   0fbf4846             | movsx               ecx, word ptr [eax + 0x46]
            //   3bd1                 | cmp                 edx, ecx
            //   7f08                 | jg                  0xa

        $sequence_12 = { 2403 80e110 8ad1 3c02 7509 }
            // n = 5, score = 400
            //   2403                 | and                 al, 3
            //   80e110               | and                 cl, 0x10
            //   8ad1                 | mov                 dl, cl
            //   3c02                 | cmp                 al, 2
            //   7509                 | jne                 0xb

        $sequence_13 = { 7408 85c0 7808 85ed }
            // n = 4, score = 400
            //   7408                 | je                  0xa
            //   85c0                 | test                eax, eax
            //   7808                 | js                  0xa
            //   85ed                 | test                ebp, ebp

        $sequence_14 = { 7409 8b4664 0fabd0 894664 }
            // n = 4, score = 400
            //   7409                 | je                  0xb
            //   8b4664               | mov                 eax, dword ptr [esi + 0x64]
            //   0fabd0               | bts                 eax, edx
            //   894664               | mov                 dword ptr [esi + 0x64], eax

    condition:
        7 of them and filesize < 11116544
}