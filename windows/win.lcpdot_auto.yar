rule win_lcpdot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lcpdot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lcpdot"
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
        $sequence_0 = { ff15???????? 488d4c2441 33d2 41b8f3010000 c644244000 e8???????? 488d1560330100 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d4c2441           | dec                 ecx
            //   33d2                 | mov                 ebp, dword ptr [ebx + 0x30]
            //   41b8f3010000         | dec                 ecx
            //   c644244000           | mov                 esp, ebx
            //   e8????????           |                     
            //   488d1560330100       | inc                 ecx

        $sequence_1 = { 488d4c2430 41b800000200 488bd7 e8???????? 85c0 753f 488b5c2430 }
            // n = 7, score = 100
            //   488d4c2430           | dec                 eax
            //   41b800000200         | mov                 dword ptr [ebp + 0x90], 0
            //   488bd7               | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [ebp + 0x98], 0
            //   753f                 | dec                 eax
            //   488b5c2430           | mov                 dword ptr [ebp + 0xa0], 0

        $sequence_2 = { 488b442438 4883c010 833800 7502 ffc3 4883c018 48ffc9 }
            // n = 7, score = 100
            //   488b442438           | dec                 eax
            //   4883c010             | mov                 edi, ebp
            //   833800               | dec                 ecx
            //   7502                 | mov                 ecx, esp
            //   ffc3                 | rep stosb           byte ptr es:[edi], al
            //   4883c018             | dec                 eax
            //   48ffc9               | mov                 ecx, ebp

        $sequence_3 = { 488b4c2448 4533c9 458d4104 488d5608 ff15???????? 4c8b442448 488b4c2440 }
            // n = 7, score = 100
            //   488b4c2448           | lea                 eax, [0x1468b]
            //   4533c9               | mov                 esi, edx
            //   458d4104             | dec                 eax
            //   488d5608             | mov                 ebx, ecx
            //   ff15????????         |                     
            //   4c8b442448           | dec                 eax
            //   488b4c2440           | mov                 dword ptr [ecx], eax

        $sequence_4 = { 4881c7e8030000 48894548 4c895e08 498b4308 }
            // n = 4, score = 100
            //   4881c7e8030000       | dec                 eax
            //   48894548             | mov                 eax, dword ptr [ecx]
            //   4c895e08             | mov                 edx, ebx
            //   498b4308             | call                dword ptr [eax + 0x48]

        $sequence_5 = { ff15???????? 418bdc 488bf0 660f1f840000000000 488b0d???????? 41b800000200 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   418bdc               | inc                 ebp
            //   488bf0               | xor                 eax, eax
            //   660f1f840000000000     | dec    eax
            //   488b0d????????       |                     
            //   41b800000200         | not                 ecx

        $sequence_6 = { 4c8d15872e0100 4885c0 7404 4c8d5010 8bcb e8???????? }
            // n = 6, score = 100
            //   4c8d15872e0100       | or                  edx, ecx
            //   4885c0               | shl                 edx, 8
            //   7404                 | shl                 ebx, 0x11
            //   4c8d5010             | inc                 esp
            //   8bcb                 | mov                 eax, ebp
            //   e8????????           |                     

        $sequence_7 = { c785f8000000101e1915 c785fc00000006ac1208 c78500010000141c0f02 c785040100003e3da293 c785080100002d230421 }
            // n = 5, score = 100
            //   c785f8000000101e1915     | mov    eax, dword ptr [ecx]
            //   c785fc00000006ac1208     | call    dword ptr [eax + 0x50]
            //   c78500010000141c0f02     | xor    eax, eax
            //   c785040100003e3da293     | dec    eax
            //   c785080100002d230421     | lea    ecx, [ebp + 0x330]

        $sequence_8 = { 498bce 4903d5 e8???????? 85c0 }
            // n = 4, score = 100
            //   498bce               | dec                 eax
            //   4903d5               | mov                 eax, dword ptr [edx + 0xc]
            //   e8????????           |                     
            //   85c0                 | mov                 ebx, 0x30

        $sequence_9 = { e8???????? 4c8d9c24d0040000 498b5b10 498b7318 498b7b20 4d8b6328 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   4c8d9c24d0040000     | inc                 ebp
            //   498b5b10             | imul                eax, eax, 0x4d10
            //   498b7318             | lea                 edx, [eax + ecx*2]
            //   498b7b20             | inc                 esp
            //   4d8b6328             | mov                 dword ptr [eax + 0x38], ebx

    condition:
        7 of them and filesize < 257024
}