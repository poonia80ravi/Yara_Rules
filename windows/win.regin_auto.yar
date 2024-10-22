rule win_regin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.regin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.regin"
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
        $sequence_0 = { 8bce e8???????? 40 0fb6cf }
            // n = 4, score = 100
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   40                   | inc                 eax
            //   0fb6cf               | movzx               ecx, bh

        $sequence_1 = { 41 b801000000 48 3bca }
            // n = 4, score = 100
            //   41                   | inc                 ecx
            //   b801000000           | mov                 eax, 1
            //   48                   | dec                 eax
            //   3bca                 | cmp                 ecx, edx

        $sequence_2 = { 8b05???????? 39442460 7405 bb01000000 85db 0f8530010000 }
            // n = 6, score = 100
            //   8b05????????         |                     
            //   39442460             | cmp                 dword ptr [esp + 0x60], eax
            //   7405                 | je                  7
            //   bb01000000           | mov                 ebx, 1
            //   85db                 | test                ebx, ebx
            //   0f8530010000         | jne                 0x136

        $sequence_3 = { 85c0 7413 49 8bf8 33c0 48 8bca }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   49                   | dec                 ecx
            //   8bf8                 | mov                 edi, eax
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   8bca                 | mov                 ecx, edx

        $sequence_4 = { 8b0b ff15???????? 3bc7 740d 33c0 48 }
            // n = 6, score = 100
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   ff15????????         |                     
            //   3bc7                 | cmp                 eax, edi
            //   740d                 | je                  0xf
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax

        $sequence_5 = { 44 8bcb 48 8bcf 89442420 c744244018000000 }
            // n = 6, score = 100
            //   44                   | inc                 esp
            //   8bcb                 | mov                 ecx, ebx
            //   48                   | dec                 eax
            //   8bcf                 | mov                 ecx, edi
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   c744244018000000     | mov                 dword ptr [esp + 0x40], 0x18

        $sequence_6 = { 8943d8 48 8d0581ffffff 49 8d4bd8 }
            // n = 5, score = 100
            //   8943d8               | mov                 dword ptr [ebx - 0x28], eax
            //   48                   | dec                 eax
            //   8d0581ffffff         | lea                 eax, [0xffffff81]
            //   49                   | dec                 ecx
            //   8d4bd8               | lea                 ecx, [ebx - 0x28]

        $sequence_7 = { 894500 8bd8 e8???????? 49 890424 48 85c0 }
            // n = 7, score = 100
            //   894500               | mov                 dword ptr [ebp], eax
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   49                   | dec                 ecx
            //   890424               | mov                 dword ptr [esp], eax
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax

        $sequence_8 = { 41 ffc0 48 8d4c2470 }
            // n = 4, score = 100
            //   41                   | inc                 ecx
            //   ffc0                 | inc                 eax
            //   48                   | dec                 eax
            //   8d4c2470             | lea                 ecx, [esp + 0x70]

        $sequence_9 = { 8bd3 ff15???????? 48 8905???????? }
            // n = 4, score = 100
            //   8bd3                 | mov                 edx, ebx
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   8905????????         |                     

    condition:
        7 of them and filesize < 49152
}