rule win_computrace_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.computrace."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.computrace"
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
        $sequence_0 = { 50 e8???????? 8d45f3 50 e8???????? 387df3 7425 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45f3               | lea                 eax, [ebp - 0xd]
            //   50                   | push                eax
            //   e8????????           |                     
            //   387df3               | cmp                 byte ptr [ebp - 0xd], bh
            //   7425                 | je                  0x27

        $sequence_1 = { 7403 50 ffd3 8bb6101b0000 85f6 }
            // n = 5, score = 200
            //   7403                 | je                  5
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8bb6101b0000         | mov                 esi, dword ptr [esi + 0x1b10]
            //   85f6                 | test                esi, esi

        $sequence_2 = { 7507 57 53 e8???????? 397de4 7423 }
            // n = 6, score = 200
            //   7507                 | jne                 9
            //   57                   | push                edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   397de4               | cmp                 dword ptr [ebp - 0x1c], edi
            //   7423                 | je                  0x25

        $sequence_3 = { 8b750c 8b7d10 57 ff7514 ff7508 e8???????? 8bd8 }
            // n = 7, score = 200
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   57                   | push                edi
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_4 = { 33db 43 833d????????00 56 751f }
            // n = 5, score = 200
            //   33db                 | xor                 ebx, ebx
            //   43                   | inc                 ebx
            //   833d????????00       |                     
            //   56                   | push                esi
            //   751f                 | jne                 0x21

        $sequence_5 = { 7506 3bdf 7d02 8bfb 8bc3 }
            // n = 5, score = 200
            //   7506                 | jne                 8
            //   3bdf                 | cmp                 ebx, edi
            //   7d02                 | jge                 4
            //   8bfb                 | mov                 edi, ebx
            //   8bc3                 | mov                 eax, ebx

        $sequence_6 = { 50 57 8d86c81b0000 50 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   57                   | push                edi
            //   8d86c81b0000         | lea                 eax, [esi + 0x1bc8]
            //   50                   | push                eax

        $sequence_7 = { 57 33ff 83c678 47 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   83c678               | add                 esi, 0x78
            //   47                   | inc                 edi

        $sequence_8 = { 56 57 8b7d08 48 48 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   48                   | dec                 eax
            //   48                   | dec                 eax

        $sequence_9 = { 8b750c 8b7d10 8b1f 837d0c00 750b 8b35???????? bb05000000 }
            // n = 7, score = 200
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   8b1f                 | mov                 ebx, dword ptr [edi]
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   750b                 | jne                 0xd
            //   8b35????????         |                     
            //   bb05000000           | mov                 ebx, 5

    condition:
        7 of them and filesize < 73728
}