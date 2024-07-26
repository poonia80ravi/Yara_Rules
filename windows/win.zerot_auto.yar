rule win_zerot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.zerot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zerot"
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
        $sequence_0 = { 41 03c1 50 8d857cf6ffff }
            // n = 4, score = 200
            //   41                   | inc                 ecx
            //   03c1                 | add                 eax, ecx
            //   50                   | push                eax
            //   8d857cf6ffff         | lea                 eax, [ebp - 0x984]

        $sequence_1 = { 8d8510fdffff 68???????? 50 e8???????? 8d8d10fdffff 83c42c }
            // n = 6, score = 200
            //   8d8510fdffff         | lea                 eax, [ebp - 0x2f0]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8d10fdffff         | lea                 ecx, [ebp - 0x2f0]
            //   83c42c               | add                 esp, 0x2c

        $sequence_2 = { ffd6 8b8d74f6ffff 41 03c1 }
            // n = 4, score = 200
            //   ffd6                 | call                esi
            //   8b8d74f6ffff         | mov                 ecx, dword ptr [ebp - 0x98c]
            //   41                   | inc                 ecx
            //   03c1                 | add                 eax, ecx

        $sequence_3 = { 6a00 ff750c 57 ff7604 }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   57                   | push                edi
            //   ff7604               | push                dword ptr [esi + 4]

        $sequence_4 = { 6a00 ff15???????? 8bc3 8d8dfcfeffff }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8bc3                 | mov                 eax, ebx
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]

        $sequence_5 = { 7527 ff35???????? ff15???????? 8b4df4 }
            // n = 4, score = 200
            //   7527                 | jne                 0x29
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_6 = { 0f8f3c010000 8b9508faffff e9???????? 8b8500faffff }
            // n = 4, score = 200
            //   0f8f3c010000         | jg                  0x142
            //   8b9508faffff         | mov                 edx, dword ptr [ebp - 0x5f8]
            //   e9????????           |                     
            //   8b8500faffff         | mov                 eax, dword ptr [ebp - 0x600]

        $sequence_7 = { 8b8d34fdffff 85c0 bf???????? 0f44fe }
            // n = 4, score = 200
            //   8b8d34fdffff         | mov                 ecx, dword ptr [ebp - 0x2cc]
            //   85c0                 | test                eax, eax
            //   bf????????           |                     
            //   0f44fe               | cmove               edi, esi

        $sequence_8 = { 83f801 750a bf???????? e9???????? 83f802 0f85f4000000 80bd4afeffff01 }
            // n = 7, score = 200
            //   83f801               | cmp                 eax, 1
            //   750a                 | jne                 0xc
            //   bf????????           |                     
            //   e9????????           |                     
            //   83f802               | cmp                 eax, 2
            //   0f85f4000000         | jne                 0xfa
            //   80bd4afeffff01       | cmp                 byte ptr [ebp - 0x1b6], 1

        $sequence_9 = { 75f9 6a40 2bcf 8d85d4feffff }
            // n = 4, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   6a40                 | push                0x40
            //   2bcf                 | sub                 ecx, edi
            //   8d85d4feffff         | lea                 eax, [ebp - 0x12c]

    condition:
        7 of them and filesize < 303104
}