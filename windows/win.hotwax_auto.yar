rule win_hotwax_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hotwax."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hotwax"
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
        $sequence_0 = { 4885c0 7413 448b07 4c8bcb ba01000000 488bc8 e8???????? }
            // n = 7, score = 100
            //   4885c0               | mov                 ecx, ebx
            //   7413                 | dec                 eax
            //   448b07               | lea                 edx, [0xd1d2]
            //   4c8bcb               | dec                 eax
            //   ba01000000           | mov                 ecx, ebx
            //   488bc8               | dec                 eax
            //   e8????????           |                     

        $sequence_1 = { 4889442420 41ff5510 488b4c2440 418bfe }
            // n = 4, score = 100
            //   4889442420           | mov                 edx, esp
            //   41ff5510             | dec                 eax
            //   488b4c2440           | mov                 ecx, esi
            //   418bfe               | inc                 ebp

        $sequence_2 = { 4489b424a0000000 4c03fa 410fb74714 4889442440 }
            // n = 4, score = 100
            //   4489b424a0000000     | dec                 eax
            //   4c03fa               | add                 eax, edx
            //   410fb74714           | dec                 eax
            //   4889442440           | cmp                 ecx, eax

        $sequence_3 = { 488bcb e8???????? 4533c0 33d2 488bcb 8907 }
            // n = 6, score = 100
            //   488bcb               | mov                 edx, 0xa
            //   e8????????           |                     
            //   4533c0               | dec                 esp
            //   33d2                 | lea                 eax, [0xffff7a92]
            //   488bcb               | cmp                 word ptr [ebp - 0x28], dx
            //   8907                 | je                  0x1c8d

        $sequence_4 = { 4883c102 413bd1 72c7 418b4204 442bd8 4c03d0 4183fb08 }
            // n = 7, score = 100
            //   4883c102             | mov                 ecx, ebx
            //   413bd1               | dec                 eax
            //   72c7                 | lea                 edx, [0xffffff6b]
            //   418b4204             | dec                 eax
            //   442bd8               | lea                 ecx, [0x10bb4]
            //   4c03d0               | dec                 eax
            //   4183fb08             | test                eax, eax

        $sequence_5 = { 66c781040100000001 c3 0fb68105010000 440fb68902010000 4c8bd1 008100010000 0fb69100010000 }
            // n = 7, score = 100
            //   66c781040100000001     | add    edi, edi
            //   c3                   | dec                 esp
            //   0fb68105010000       | lea                 ebp, [0x98c1]
            //   440fb68902010000     | dec                 ecx
            //   4c8bd1               | cmp                 dword ptr [ebp + edi*8], 0
            //   008100010000         | je                  0x163e
            //   0fb69100010000       | dec                 eax

        $sequence_6 = { 4c8b642450 0f84c5000000 488364242000 488d0571a60000 c64424600d 4a8b0ce0 }
            // n = 6, score = 100
            //   4c8b642450           | lea                 eax, [0x938a]
            //   0f84c5000000         | dec                 ebx
            //   488364242000         | sub                 ebx, dword ptr [eax + esi*8]
            //   488d0571a60000       | dec                 eax
            //   c64424600d           | mov                 eax, 0xba2e8ba3
            //   4a8b0ce0             | call                0xc62ea0f9

        $sequence_7 = { 443bd8 7c44 33d2 4585c9 743d 498d4a08 0fb701 }
            // n = 7, score = 100
            //   443bd8               | dec                 eax
            //   7c44                 | mov                 edi, edx
            //   33d2                 | dec                 eax
            //   4585c9               | mov                 ebx, ecx
            //   743d                 | dec                 eax
            //   498d4a08             | lea                 eax, [0x9f99]
            //   0fb701               | dec                 eax

        $sequence_8 = { b81a000000 eb76 33c9 488d158bb70000 }
            // n = 4, score = 100
            //   b81a000000           | dec                 esp
            //   eb76                 | mov                 ebx, eax
            //   33c9                 | dec                 ebx
            //   488d158bb70000       | mov                 eax, dword ptr [ecx + edi*8 + 0x14ba0]

        $sequence_9 = { 458d60f8 4488443039 4180fd01 752e 4b8b84f9a04b0100 8a4c303a }
            // n = 6, score = 100
            //   458d60f8             | inc                 ecx
            //   4488443039           | mov                 ecx, 4
            //   4180fd01             | dec                 eax
            //   752e                 | or                  ecx, 0xffffffff
            //   4b8b84f9a04b0100     | dec                 eax
            //   8a4c303a             | mov                 dword ptr [esp + 0x20], eax

    condition:
        7 of them and filesize < 198656
}