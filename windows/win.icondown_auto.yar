rule win_icondown_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.icondown."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icondown"
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
        $sequence_0 = { a1???????? 8d8e6c010000 8901 8b15???????? 8dbe70010000 }
            // n = 5, score = 200
            //   a1????????           |                     
            //   8d8e6c010000         | lea                 ecx, [esi + 0x16c]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b15????????         |                     
            //   8dbe70010000         | lea                 edi, [esi + 0x170]

        $sequence_1 = { 56 57 8b7c2410 8bf1 6a00 6a00 c70700000000 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   8bf1                 | mov                 esi, ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   c70700000000         | mov                 dword ptr [edi], 0

        $sequence_2 = { 3bc5 7c10 5f 5e 5d b8feffffff 5b }
            // n = 7, score = 200
            //   3bc5                 | cmp                 eax, ebp
            //   7c10                 | jl                  0x12
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   b8feffffff           | mov                 eax, 0xfffffffe
            //   5b                   | pop                 ebx

        $sequence_3 = { b274 b061 b32e 88542411 88542412 }
            // n = 5, score = 200
            //   b274                 | mov                 dl, 0x74
            //   b061                 | mov                 al, 0x61
            //   b32e                 | mov                 bl, 0x2e
            //   88542411             | mov                 byte ptr [esp + 0x11], dl
            //   88542412             | mov                 byte ptr [esp + 0x12], dl

        $sequence_4 = { 8b442438 c644243001 25ffff0000 50 6a00 ff15???????? 50 }
            // n = 7, score = 200
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   c644243001           | mov                 byte ptr [esp + 0x30], 1
            //   25ffff0000           | and                 eax, 0xffff
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_5 = { 83c404 e8???????? 85c0 7538 e8???????? e8???????? e8???????? }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7538                 | jne                 0x3a
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_6 = { 394810 740c 8b4008 85c0 }
            // n = 4, score = 200
            //   394810               | cmp                 dword ptr [eax + 0x10], ecx
            //   740c                 | je                  0xe
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   85c0                 | test                eax, eax

        $sequence_7 = { 6a00 6804130000 52 46 }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   6804130000           | push                0x1304
            //   52                   | push                edx
            //   46                   | inc                 esi

        $sequence_8 = { 7415 8b4c2418 8b10 55 51 8b4c241c }
            // n = 6, score = 200
            //   7415                 | je                  0x17
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   55                   | push                ebp
            //   51                   | push                ecx
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]

        $sequence_9 = { 57 33ff 8bf1 57 53 89742414 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   53                   | push                ebx
            //   89742414             | mov                 dword ptr [esp + 0x14], esi

    condition:
        7 of them and filesize < 5505024
}