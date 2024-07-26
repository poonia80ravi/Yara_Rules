rule win_yarat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.yarat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yarat"
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
        $sequence_0 = { 8975f4 80be9c08000000 750c 85ff 7408 5f 33c0 }
            // n = 7, score = 100
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   80be9c08000000       | cmp                 byte ptr [esi + 0x89c], 0
            //   750c                 | jne                 0xe
            //   85ff                 | test                edi, edi
            //   7408                 | je                  0xa
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 8bcb 8d7101 0f1f440000 8a01 41 84c0 75f9 }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   8d7101               | lea                 esi, [ecx + 1]
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb

        $sequence_2 = { 8b16 80d122 d3c8 8a4e04 0473 66d3d8 66c1e072 }
            // n = 7, score = 100
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   80d122               | adc                 cl, 0x22
            //   d3c8                 | ror                 eax, cl
            //   8a4e04               | mov                 cl, byte ptr [esi + 4]
            //   0473                 | add                 al, 0x73
            //   66d3d8               | rcr                 ax, cl
            //   66c1e072             | shl                 ax, 0x72

        $sequence_3 = { f7d1 41 f9 f5 d1c9 85c1 f7c2252c8c12 }
            // n = 7, score = 100
            //   f7d1                 | not                 ecx
            //   41                   | inc                 ecx
            //   f9                   | stc                 
            //   f5                   | cmc                 
            //   d1c9                 | ror                 ecx, 1
            //   85c1                 | test                ecx, eax
            //   f7c2252c8c12         | test                edx, 0x128c2c25

        $sequence_4 = { 8b55b8 8bc2 8b4db4 2bc1 83f802 7223 8d4102 }
            // n = 7, score = 100
            //   8b55b8               | mov                 edx, dword ptr [ebp - 0x48]
            //   8bc2                 | mov                 eax, edx
            //   8b4db4               | mov                 ecx, dword ptr [ebp - 0x4c]
            //   2bc1                 | sub                 eax, ecx
            //   83f802               | cmp                 eax, 2
            //   7223                 | jb                  0x25
            //   8d4102               | lea                 eax, [ecx + 2]

        $sequence_5 = { c3 8b45f8 8d4df0 51 8d4df4 51 50 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   51                   | push                ecx
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_6 = { 89857cffffff 8b856cffffff 894598 8b8568ffffff 894590 8b8564ffffff 8b4d90 }
            // n = 7, score = 100
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax
            //   8b856cffffff         | mov                 eax, dword ptr [ebp - 0x94]
            //   894598               | mov                 dword ptr [ebp - 0x68], eax
            //   8b8568ffffff         | mov                 eax, dword ptr [ebp - 0x98]
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   8b8564ffffff         | mov                 eax, dword ptr [ebp - 0x9c]
            //   8b4d90               | mov                 ecx, dword ptr [ebp - 0x70]

        $sequence_7 = { 8b4518 53 56 57 c70000000000 8b450c 85c0 }
            // n = 7, score = 100
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   85c0                 | test                eax, eax

        $sequence_8 = { e8???????? 8be5 5d c3 83f801 0f85b9000000 6a0a }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   83f801               | cmp                 eax, 1
            //   0f85b9000000         | jne                 0xbf
            //   6a0a                 | push                0xa

        $sequence_9 = { 8be5 5d c3 8b4510 ff30 8b4508 0590090000 }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   ff30                 | push                dword ptr [eax]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0590090000           | add                 eax, 0x990

    condition:
        7 of them and filesize < 8692736
}