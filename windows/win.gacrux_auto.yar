rule win_gacrux_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gacrux."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gacrux"
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
        $sequence_0 = { 32f6 4c 8be9 4c }
            // n = 4, score = 300
            //   32f6                 | xor                 dh, dh
            //   4c                   | dec                 esp
            //   8be9                 | mov                 ebp, ecx
            //   4c                   | dec                 esp

        $sequence_1 = { b800800000 ff5330 4c 8b4358 48 8b5330 }
            // n = 6, score = 300
            //   b800800000           | mov                 eax, 0x8000
            //   ff5330               | call                dword ptr [ebx + 0x30]
            //   4c                   | dec                 esp
            //   8b4358               | mov                 eax, dword ptr [ebx + 0x58]
            //   48                   | dec                 eax
            //   8b5330               | mov                 edx, dword ptr [ebx + 0x30]

        $sequence_2 = { 72f2 41 c7462001000000 49 8b4608 41 }
            // n = 6, score = 300
            //   72f2                 | jb                  0xfffffff4
            //   41                   | inc                 ecx
            //   c7462001000000       | mov                 dword ptr [esi + 0x20], 1
            //   49                   | dec                 ecx
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   41                   | inc                 ecx

        $sequence_3 = { 8bcb 44 8bc7 48 8bd6 48 8bcd }
            // n = 7, score = 300
            //   8bcb                 | mov                 ecx, ebx
            //   44                   | inc                 esp
            //   8bc7                 | mov                 eax, edi
            //   48                   | dec                 eax
            //   8bd6                 | mov                 edx, esi
            //   48                   | dec                 eax
            //   8bcd                 | mov                 ecx, ebp

        $sequence_4 = { 3bc8 72eb 4c 3b5208 0f8536ffffff 48 8b0a }
            // n = 7, score = 300
            //   3bc8                 | cmp                 ecx, eax
            //   72eb                 | jb                  0xffffffed
            //   4c                   | dec                 esp
            //   3b5208               | cmp                 edx, dword ptr [edx + 8]
            //   0f8536ffffff         | jne                 0xffffff3c
            //   48                   | dec                 eax
            //   8b0a                 | mov                 ecx, dword ptr [edx]

        $sequence_5 = { ffd0 48 03df 33c0 f00fb13d???????? 75d6 48 }
            // n = 7, score = 300
            //   ffd0                 | call                eax
            //   48                   | dec                 eax
            //   03df                 | add                 ebx, edi
            //   33c0                 | xor                 eax, eax
            //   f00fb13d????????     |                     
            //   75d6                 | jne                 0xffffffd8
            //   48                   | dec                 eax

        $sequence_6 = { 7533 837a1c00 751c 49 8b02 41 8b5268 }
            // n = 7, score = 300
            //   7533                 | jne                 0x35
            //   837a1c00             | cmp                 dword ptr [edx + 0x1c], 0
            //   751c                 | jne                 0x1e
            //   49                   | dec                 ecx
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   41                   | inc                 ecx
            //   8b5268               | mov                 edx, dword ptr [edx + 0x68]

        $sequence_7 = { 90 90 90 41 b800020000 bacc000000 }
            // n = 6, score = 300
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   41                   | inc                 ecx
            //   b800020000           | mov                 eax, 0x200
            //   bacc000000           | mov                 edx, 0xcc

        $sequence_8 = { 72c9 48 8d4c2420 e8???????? 48 8b5c2440 8bc7 }
            // n = 7, score = 300
            //   72c9                 | jb                  0xffffffcb
            //   48                   | dec                 eax
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8b5c2440             | mov                 ebx, dword ptr [esp + 0x40]
            //   8bc7                 | mov                 eax, edi

        $sequence_9 = { b9e9fd0000 ffd0 48 8bf0 85c0 7444 8d4801 }
            // n = 7, score = 300
            //   b9e9fd0000           | mov                 ecx, 0xfde9
            //   ffd0                 | call                eax
            //   48                   | dec                 eax
            //   8bf0                 | mov                 esi, eax
            //   85c0                 | test                eax, eax
            //   7444                 | je                  0x46
            //   8d4801               | lea                 ecx, [eax + 1]

    condition:
        7 of them and filesize < 122880
}