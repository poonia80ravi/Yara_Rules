rule win_sunorcal_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sunorcal."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sunorcal"
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
        $sequence_0 = { c21000 8b442404 8b00 813863736de0 752a 83781003 }
            // n = 6, score = 200
            //   c21000               | ret                 0x10
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   813863736de0         | cmp                 dword ptr [eax], 0xe06d7363
            //   752a                 | jne                 0x2c
            //   83781003             | cmp                 dword ptr [eax + 0x10], 3

        $sequence_1 = { 50 6a00 ff15???????? 6800040000 e8???????? }
            // n = 5, score = 200
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6800040000           | push                0x400
            //   e8????????           |                     

        $sequence_2 = { eb0e e8???????? e8???????? 85c0 }
            // n = 4, score = 200
            //   eb0e                 | jmp                 0x10
            //   e8????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { ff15???????? 68b7000000 ff15???????? 6a64 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   68b7000000           | push                0xb7
            //   ff15????????         |                     
            //   6a64                 | push                0x64

        $sequence_4 = { 5b c21000 8b442404 8b00 813863736de0 752a }
            // n = 6, score = 200
            //   5b                   | pop                 ebx
            //   c21000               | ret                 0x10
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   813863736de0         | cmp                 dword ptr [eax], 0xe06d7363
            //   752a                 | jne                 0x2c

        $sequence_5 = { 7c02 eb0e e8???????? e8???????? }
            // n = 4, score = 200
            //   7c02                 | jl                  4
            //   eb0e                 | jmp                 0x10
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_6 = { 8bc6 5e 5b c21000 8b442404 8b00 }
            // n = 6, score = 200
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c21000               | ret                 0x10
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_7 = { 7c02 eb0e e8???????? e8???????? 85c0 }
            // n = 5, score = 200
            //   7c02                 | jl                  4
            //   eb0e                 | jmp                 0x10
            //   e8????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_8 = { 5b c21000 8b442404 8b00 813863736de0 }
            // n = 5, score = 200
            //   5b                   | pop                 ebx
            //   c21000               | ret                 0x10
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   813863736de0         | cmp                 dword ptr [eax], 0xe06d7363

        $sequence_9 = { c21000 8b442404 8b00 813863736de0 }
            // n = 4, score = 200
            //   c21000               | ret                 0x10
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   813863736de0         | cmp                 dword ptr [eax], 0xe06d7363

    condition:
        7 of them and filesize < 172032
}