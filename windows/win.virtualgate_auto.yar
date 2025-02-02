rule win_virtualgate_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.virtualgate."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virtualgate"
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
        $sequence_0 = { 803c0800 75f7 b800200000 488d5c2470 2bc1 488dac24b8200000 }
            // n = 6, score = 100
            //   803c0800             | mov                 ecx, dword ptr [esi + eax*4 + 0x12770]
            //   75f7                 | dec                 eax
            //   b800200000           | add                 ecx, esi
            //   488d5c2470           | jmp                 ecx
            //   2bc1                 | pslldq              xmm1, 1
            //   488dac24b8200000     | psrldq              xmm1, 1

        $sequence_1 = { 4c8d0dd5cf0000 488bd9 488d15cbcf0000 b916000000 4c8d05b7cf0000 e8???????? }
            // n = 6, score = 100
            //   4c8d0dd5cf0000       | dec                 eax
            //   488bd9               | and                 dword ptr [ebx + 8], 0
            //   488d15cbcf0000       | dec                 eax
            //   b916000000           | and                 dword ptr [ebx], 0
            //   4c8d05b7cf0000       | dec                 eax
            //   e8????????           |                     

        $sequence_2 = { 488b03 833800 7513 488d151df90000 488d0df6f80000 e8???????? }
            // n = 6, score = 100
            //   488b03               | dec                 esp
            //   833800               | lea                 edx, [0x1cf83]
            //   7513                 | dec                 esp
            //   488d151df90000       | lea                 ebx, [0x1e3fc]
            //   488d0df6f80000       | dec                 ebp
            //   e8????????           |                     

        $sequence_3 = { 4c896c2470 4c896c2478 4c896d87 4c896d8f 4c896d97 44886d9f e8???????? }
            // n = 7, score = 100
            //   4c896c2470           | xor                 ecx, esp
            //   4c896c2478           | je                  0x14e
            //   4c896d87             | dec                 eax
            //   4c896d8f             | mov                 edx, ebx
            //   4c896d97             | dec                 esp
            //   44886d9f             | lea                 eax, [0xddf2]
            //   e8????????           |                     

        $sequence_4 = { 480f44d9 488d4c2440 4c8bc3 e8???????? 33c0 4c8d442440 4889442438 }
            // n = 7, score = 100
            //   480f44d9             | xor                 ecx, ecx
            //   488d4c2440           | mov                 dword ptr [esp + 0x20], 3
            //   4c8bc3               | inc                 ebp
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   4c8d442440           | mov                 dword ptr [esp + 0x40], 0xffffffff
            //   4889442438           | mov                 edx, 0x80000000

        $sequence_5 = { 488d15e1d20000 e8???????? 4885c0 740b 4883c428 48ff25???????? b801000000 }
            // n = 7, score = 100
            //   488d15e1d20000       | dec                 eax
            //   e8????????           |                     
            //   4885c0               | sar                 eax, 6
            //   740b                 | dec                 eax
            //   4883c428             | lea                 edx, [ecx + ecx*8]
            //   48ff25????????       |                     
            //   b801000000           | dec                 ecx

        $sequence_6 = { 7511 488d0d64d60100 e8???????? e9???????? }
            // n = 4, score = 100
            //   7511                 | mov                 dword ptr [esp + 0x20], ebx
            //   488d0d64d60100       | dec                 eax
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_7 = { 0f84b8000000 4983cdff 498bcd 48ffc1 40383c0b 75f7 4803cb }
            // n = 7, score = 100
            //   0f84b8000000         | jne                 0x7db
            //   4983cdff             | mov                 dword ptr [eax], 0x16
            //   498bcd               | dec                 eax
            //   48ffc1               | sub                 esp, 0x30
            //   40383c0b             | dec                 ecx
            //   75f7                 | mov                 edi, ecx
            //   4803cb               | mov                 ecx, dword ptr [edx]

        $sequence_8 = { 4b8b8cd7f0250200 4903c8 49ffc0 428844d93e 4963c1 483bc2 }
            // n = 6, score = 100
            //   4b8b8cd7f0250200     | inc                 esp
            //   4903c8               | cmp                 eax, ecx
            //   49ffc0               | cmove               eax, ecx
            //   428844d93e           | mov                 ecx, edi
            //   4963c1               | mov                 ecx, 3
            //   483bc2               | dec                 esp

        $sequence_9 = { e9???????? 4183f801 0f85b7000000 448905???????? }
            // n = 4, score = 100
            //   e9????????           |                     
            //   4183f801             | dec                 ecx
            //   0f85b7000000         | cmp                 eax, esi
            //   448905????????       |                     

    condition:
        7 of them and filesize < 323584
}