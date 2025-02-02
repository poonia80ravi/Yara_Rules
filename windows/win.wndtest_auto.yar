rule win_wndtest_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.wndtest."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wndtest"
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
        $sequence_0 = { 56 e8???????? 53 e8???????? 83c40c 57 }
            // n = 6, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   57                   | push                edi

        $sequence_1 = { 8d4de0 51 ffd7 8d55e0 52 ffd3 }
            // n = 6, score = 400
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   8d55e0               | lea                 edx, [ebp - 0x20]
            //   52                   | push                edx
            //   ffd3                 | call                ebx

        $sequence_2 = { 0f858d000000 8b1d???????? 6a10 8945e8 8d45e8 50 6a00 }
            // n = 7, score = 400
            //   0f858d000000         | jne                 0x93
            //   8b1d????????         |                     
            //   6a10                 | push                0x10
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_3 = { 51 53 56 83cbff 33f6 }
            // n = 5, score = 400
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   83cbff               | or                  ebx, 0xffffffff
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { 8da42400000000 85c0 7909 03c0 35b71dc104 }
            // n = 5, score = 400
            //   8da42400000000       | lea                 esp, [esp]
            //   85c0                 | test                eax, eax
            //   7909                 | jns                 0xb
            //   03c0                 | add                 eax, eax
            //   35b71dc104           | xor                 eax, 0x4c11db7

        $sequence_5 = { 57 e8???????? 8bbdf8feffff 8bd7 }
            // n = 4, score = 400
            //   57                   | push                edi
            //   e8????????           |                     
            //   8bbdf8feffff         | mov                 edi, dword ptr [ebp - 0x108]
            //   8bd7                 | mov                 edx, edi

        $sequence_6 = { 894614 894618 89461c 8907 894704 894708 }
            // n = 6, score = 400
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   894618               | mov                 dword ptr [esi + 0x18], eax
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax
            //   8907                 | mov                 dword ptr [edi], eax
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   894708               | mov                 dword ptr [edi + 8], eax

        $sequence_7 = { 56 0fbe7001 33750c 57 8d4e01 51 }
            // n = 6, score = 400
            //   56                   | push                esi
            //   0fbe7001             | movsx               esi, byte ptr [eax + 1]
            //   33750c               | xor                 esi, dword ptr [ebp + 0xc]
            //   57                   | push                edi
            //   8d4e01               | lea                 ecx, [esi + 1]
            //   51                   | push                ecx

        $sequence_8 = { 50 51 e8???????? 8b3d???????? 83c408 50 }
            // n = 6, score = 400
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   83c408               | add                 esp, 8
            //   50                   | push                eax

        $sequence_9 = { 8bf0 56 6803000010 57 ffd3 85c0 741c }
            // n = 7, score = 400
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   6803000010           | push                0x10000003
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   741c                 | je                  0x1e

    condition:
        7 of them and filesize < 901120
}