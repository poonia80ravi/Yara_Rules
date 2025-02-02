rule win_mongall_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mongall."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mongall"
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
        $sequence_0 = { 0f84a2000000 6a02 6a00 6a00 53 }
            // n = 5, score = 100
            //   0f84a2000000         | je                  0xa8
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   53                   | push                ebx

        $sequence_1 = { 7538 384705 7533 6a5c 6a00 8d95f8feffff }
            // n = 6, score = 100
            //   7538                 | jne                 0x3a
            //   384705               | cmp                 byte ptr [edi + 5], al
            //   7533                 | jne                 0x35
            //   6a5c                 | push                0x5c
            //   6a00                 | push                0
            //   8d95f8feffff         | lea                 edx, [ebp - 0x108]

        $sequence_2 = { 6a00 8d8574f9ffff 50 6a00 ff15???????? 85c0 742c }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   8d8574f9ffff         | lea                 eax, [ebp - 0x68c]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742c                 | je                  0x2e

        $sequence_3 = { 6a00 ff15???????? 85c0 742c 8b8d58f8ffff }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742c                 | je                  0x2e
            //   8b8d58f8ffff         | mov                 ecx, dword ptr [ebp - 0x7a8]

        $sequence_4 = { 0f846f010000 56 ff15???????? 53 8bf0 }
            // n = 5, score = 100
            //   0f846f010000         | je                  0x175
            //   56                   | push                esi
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 8945fc 8b4508 53 56 898574ffffff 8b450c 57 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   898574ffffff         | mov                 dword ptr [ebp - 0x8c], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   57                   | push                edi

        $sequence_6 = { 50 ffd6 eb06 8b35???????? 6a00 6880000000 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   eb06                 | jmp                 8
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   6880000000           | push                0x80

        $sequence_7 = { eb02 33c0 8985f8fdffff 68???????? ff15???????? 8d7001 81feffffff3f }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   8985f8fdffff         | mov                 dword ptr [ebp - 0x208], eax
            //   68????????           |                     
            //   ff15????????         |                     
            //   8d7001               | lea                 esi, [eax + 1]
            //   81feffffff3f         | cmp                 esi, 0x3fffffff

        $sequence_8 = { 8b4d08 68???????? 6a18 53 ba???????? e8???????? 83c410 }
            // n = 7, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   68????????           |                     
            //   6a18                 | push                0x18
            //   53                   | push                ebx
            //   ba????????           |                     
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_9 = { 72ee 33c0 5d c3 8b04c5dcee4000 }
            // n = 5, score = 100
            //   72ee                 | jb                  0xfffffff0
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c5dcee4000       | mov                 eax, dword ptr [eax*8 + 0x40eedc]

    condition:
        7 of them and filesize < 199680
}