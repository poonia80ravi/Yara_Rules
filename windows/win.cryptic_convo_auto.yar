rule win_cryptic_convo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.cryptic_convo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptic_convo"
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
        $sequence_0 = { 83c40c 8b7da4 8b45b4 6a10 59 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8b7da4               | mov                 edi, dword ptr [ebp - 0x5c]
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   6a10                 | push                0x10
            //   59                   | pop                 ecx

        $sequence_1 = { a5 a5 8d85c0fdffff 50 66a5 ff15???????? 8bd8 }
            // n = 7, score = 100
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   8d85c0fdffff         | lea                 eax, [ebp - 0x240]
            //   50                   | push                eax
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_2 = { a1???????? 33c5 8985a4050000 8b85b0050000 }
            // n = 4, score = 100
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8985a4050000         | mov                 dword ptr [ebp + 0x5a4], eax
            //   8b85b0050000         | mov                 eax, dword ptr [ebp + 0x5b0]

        $sequence_3 = { be???????? a5 66a5 8d7dc8 4f 8a4701 }
            // n = 6, score = 100
            //   be????????           |                     
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   8d7dc8               | lea                 edi, [ebp - 0x38]
            //   4f                   | dec                 edi
            //   8a4701               | mov                 al, byte ptr [edi + 1]

        $sequence_4 = { 53 eb25 803d????????01 741b 803d????????01 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   eb25                 | jmp                 0x27
            //   803d????????01       |                     
            //   741b                 | je                  0x1d
            //   803d????????01       |                     

        $sequence_5 = { ff15???????? 53 57 894588 ff15???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   57                   | push                edi
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   ff15????????         |                     

        $sequence_6 = { 8985acfeffff ffd6 ffb5acfeffff 8985b0feffff ffd6 }
            // n = 5, score = 100
            //   8985acfeffff         | mov                 dword ptr [ebp - 0x154], eax
            //   ffd6                 | call                esi
            //   ffb5acfeffff         | push                dword ptr [ebp - 0x154]
            //   8985b0feffff         | mov                 dword ptr [ebp - 0x150], eax
            //   ffd6                 | call                esi

        $sequence_7 = { 8d45c8 a5 50 ff35???????? a4 }
            // n = 5, score = 100
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   50                   | push                eax
            //   ff35????????         |                     
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]

        $sequence_8 = { 56 57 6a00 6a02 e8???????? 68???????? 8985b4fbffff }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   e8????????           |                     
            //   68????????           |                     
            //   8985b4fbffff         | mov                 dword ptr [ebp - 0x44c], eax

        $sequence_9 = { 8985d0030000 8b85dc030000 83658000 8945e4 8b85e0030000 6a40 }
            // n = 6, score = 100
            //   8985d0030000         | mov                 dword ptr [ebp + 0x3d0], eax
            //   8b85dc030000         | mov                 eax, dword ptr [ebp + 0x3dc]
            //   83658000             | and                 dword ptr [ebp - 0x80], 0
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b85e0030000         | mov                 eax, dword ptr [ebp + 0x3e0]
            //   6a40                 | push                0x40

    condition:
        7 of them and filesize < 97280
}