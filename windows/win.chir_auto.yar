rule win_chir_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.chir."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chir"
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
        $sequence_0 = { 5e 7419 8d4c35f8 8a11 80f2fc 80c202 80f201 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   7419                 | je                  0x1b
            //   8d4c35f8             | lea                 ecx, [ebp + esi - 8]
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   80f2fc               | xor                 dl, 0xfc
            //   80c202               | add                 dl, 2
            //   80f201               | xor                 dl, 1

        $sequence_1 = { 50 c745f021352432 c745f451173300 e8???????? }
            // n = 4, score = 300
            //   50                   | push                eax
            //   c745f021352432       | mov                 dword ptr [ebp - 0x10], 0x32243521
            //   c745f451173300       | mov                 dword ptr [ebp - 0xc], 0x331751
            //   e8????????           |                     

        $sequence_2 = { 48 59 8bfb 7419 }
            // n = 4, score = 300
            //   48                   | dec                 eax
            //   59                   | pop                 ecx
            //   8bfb                 | mov                 edi, ebx
            //   7419                 | je                  0x1b

        $sequence_3 = { 8d45f8 50 c745f821352432 c745fc51173300 }
            // n = 4, score = 300
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   c745f821352432       | mov                 dword ptr [ebp - 8], 0x32243521
            //   c745fc51173300       | mov                 dword ptr [ebp - 4], 0x331751

        $sequence_4 = { 80f201 80c203 47 8811 3bf8 72e7 ff75fc }
            // n = 7, score = 300
            //   80f201               | xor                 dl, 1
            //   80c203               | add                 dl, 3
            //   47                   | inc                 edi
            //   8811                 | mov                 byte ptr [ecx], dl
            //   3bf8                 | cmp                 edi, eax
            //   72e7                 | jb                  0xffffffe9
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_5 = { c745fc32212400 e8???????? 59 33c9 807df905 }
            // n = 5, score = 300
            //   c745fc32212400       | mov                 dword ptr [ebp - 4], 0x242132
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   33c9                 | xor                 ecx, ecx
            //   807df905             | cmp                 byte ptr [ebp - 7], 5

        $sequence_6 = { c745f021352432 c745f451173300 e8???????? 48 }
            // n = 4, score = 300
            //   c745f021352432       | mov                 dword ptr [ebp - 0x10], 0x32243521
            //   c745f451173300       | mov                 dword ptr [ebp - 0xc], 0x331751
            //   e8????????           |                     
            //   48                   | dec                 eax

        $sequence_7 = { c745fc32212400 e8???????? 59 33c9 }
            // n = 4, score = 300
            //   c745fc32212400       | mov                 dword ptr [ebp - 4], 0x242132
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   33c9                 | xor                 ecx, ecx

        $sequence_8 = { 6a00 5e 7419 8d4c35f8 8a11 80f2fc 80c202 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   5e                   | pop                 esi
            //   7419                 | je                  0x1b
            //   8d4c35f8             | lea                 ecx, [ebp + esi - 8]
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   80f2fc               | xor                 dl, 0xfc
            //   80c202               | add                 dl, 2

        $sequence_9 = { 48 8906 66837c47fe5c 75ef 8b06 33c9 66890c47 }
            // n = 7, score = 300
            //   48                   | dec                 eax
            //   8906                 | mov                 dword ptr [esi], eax
            //   66837c47fe5c         | cmp                 word ptr [edi + eax*2 - 2], 0x5c
            //   75ef                 | jne                 0xfffffff1
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   33c9                 | xor                 ecx, ecx
            //   66890c47             | mov                 word ptr [edi + eax*2], cx

    condition:
        7 of them and filesize < 286720
}