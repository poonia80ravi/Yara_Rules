rule win_fakeword_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.fakeword."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fakeword"
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
        $sequence_0 = { 50 c6400421 895005 894809 8b15???????? 89500d c7000d000000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   c6400421             | mov                 byte ptr [eax + 4], 0x21
            //   895005               | mov                 dword ptr [eax + 5], edx
            //   894809               | mov                 dword ptr [eax + 9], ecx
            //   8b15????????         |                     
            //   89500d               | mov                 dword ptr [eax + 0xd], edx
            //   c7000d000000         | mov                 dword ptr [eax], 0xd

        $sequence_1 = { 885c29ff 41 8d41ff 3bc2 7cbd 5d 5b }
            // n = 7, score = 200
            //   885c29ff             | mov                 byte ptr [ecx + ebp - 1], bl
            //   41                   | inc                 ecx
            //   8d41ff               | lea                 eax, [ecx - 1]
            //   3bc2                 | cmp                 eax, edx
            //   7cbd                 | jl                  0xffffffbf
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_2 = { 6a45 68???????? 56 ffd3 83c40c c70604000000 56 }
            // n = 7, score = 200
            //   6a45                 | push                0x45
            //   68????????           |                     
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   83c40c               | add                 esp, 0xc
            //   c70604000000         | mov                 dword ptr [esi], 4
            //   56                   | push                esi

        $sequence_3 = { 57 ffd5 53 8d4c2414 68???????? 51 ff15???????? }
            // n = 7, score = 200
            //   57                   | push                edi
            //   ffd5                 | call                ebp
            //   53                   | push                ebx
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_4 = { e8???????? 6a42 6a10 68???????? 6a28 68???????? }
            // n = 6, score = 200
            //   e8????????           |                     
            //   6a42                 | push                0x42
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   6a28                 | push                0x28
            //   68????????           |                     

        $sequence_5 = { 0f8520020000 8b9c2424110000 8b03 3da0000000 0f85f2010000 c705????????01000000 a1???????? }
            // n = 7, score = 200
            //   0f8520020000         | jne                 0x226
            //   8b9c2424110000       | mov                 ebx, dword ptr [esp + 0x1124]
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   3da0000000           | cmp                 eax, 0xa0
            //   0f85f2010000         | jne                 0x1f8
            //   c705????????01000000     |     
            //   a1????????           |                     

        $sequence_6 = { 51 ff15???????? 83c404 c705????????00000000 c705????????00000000 c705????????00000000 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   c705????????00000000     |     

        $sequence_7 = { 57 ff15???????? 8bd8 85db 7507 5f 5e }
            // n = 7, score = 200
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   7507                 | jne                 9
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { 59 c3 56 e8???????? 8b442410 83c404 5f }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi

        $sequence_9 = { 7560 e8???????? 83f8ff 7456 68???????? 68???????? 68???????? }
            // n = 7, score = 200
            //   7560                 | jne                 0x62
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7456                 | je                  0x58
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     

    condition:
        7 of them and filesize < 98304
}