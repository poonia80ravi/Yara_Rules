rule win_gamotrol_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gamotrol."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gamotrol"
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
        $sequence_0 = { 57 ffd6 3bc3 a3???????? 7433 68???????? 57 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   3bc3                 | cmp                 eax, ebx
            //   a3????????           |                     
            //   7433                 | je                  0x35
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_1 = { 6aff 68???????? 68???????? 6a00 ff15???????? 6804010000 8d8544fcffff }
            // n = 7, score = 100
            //   6aff                 | push                -1
            //   68????????           |                     
            //   68????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6804010000           | push                0x104
            //   8d8544fcffff         | lea                 eax, [ebp - 0x3bc]

        $sequence_2 = { 49 90 90 8be5 5d 57 56 }
            // n = 7, score = 100
            //   49                   | dec                 ecx
            //   90                   | nop                 
            //   90                   | nop                 
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_3 = { e8???????? 8b442408 c706???????? c7463054dd2e00 c74634c8dd2e00 894620 33c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   c706????????         |                     
            //   c7463054dd2e00       | mov                 dword ptr [esi + 0x30], 0x2edd54
            //   c74634c8dd2e00       | mov                 dword ptr [esi + 0x34], 0x2eddc8
            //   894620               | mov                 dword ptr [esi + 0x20], eax
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 90 5d 8b00 6683780600 0fb74814 }
            // n = 5, score = 100
            //   90                   | nop                 
            //   5d                   | pop                 ebp
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   6683780600           | cmp                 word ptr [eax + 6], 0
            //   0fb74814             | movzx               ecx, word ptr [eax + 0x14]

        $sequence_5 = { 8d45ac 50 8d8d48fdffff b365 51 }
            // n = 5, score = 100
            //   8d45ac               | lea                 eax, [ebp - 0x54]
            //   50                   | push                eax
            //   8d8d48fdffff         | lea                 ecx, [ebp - 0x2b8]
            //   b365                 | mov                 bl, 0x65
            //   51                   | push                ecx

        $sequence_6 = { 85f6 751f 8b5350 6a04 6800200000 52 50 }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   751f                 | jne                 0x21
            //   8b5350               | mov                 edx, dword ptr [ebx + 0x50]
            //   6a04                 | push                4
            //   6800200000           | push                0x2000
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_7 = { e8???????? 5e c20400 56 8bf1 8b06 33c9 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   33c9                 | xor                 ecx, ecx

        $sequence_8 = { 81ec00020000 8d6c24fc a1???????? 33c5 898500020000 6a0c b8???????? }
            // n = 7, score = 100
            //   81ec00020000         | sub                 esp, 0x200
            //   8d6c24fc             | lea                 ebp, [esp - 4]
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   898500020000         | mov                 dword ptr [ebp + 0x200], eax
            //   6a0c                 | push                0xc
            //   b8????????           |                     

        $sequence_9 = { 55 8bec 8b4508 ff34c5b04b2f00 ff15???????? 5d }
            // n = 6, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c5b04b2f00       | push                dword ptr [eax*8 + 0x2f4bb0]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp

    condition:
        7 of them and filesize < 376832
}