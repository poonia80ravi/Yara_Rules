rule win_greenshaitan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.greenshaitan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.greenshaitan"
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
        $sequence_0 = { 57 a1???????? 33c4 50 8d44240c 64a300000000 8b461c }
            // n = 7, score = 100
            //   57                   | push                edi
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   50                   | push                eax
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]

        $sequence_1 = { 56 8d442404 8bf1 50 8d4c240c c744240800000000 51 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8d442404             | lea                 eax, [esp + 4]
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   51                   | push                ecx

        $sequence_2 = { 899f30010000 899f34010000 899f74010000 899f70010000 8d877c010000 50 }
            // n = 6, score = 100
            //   899f30010000         | mov                 dword ptr [edi + 0x130], ebx
            //   899f34010000         | mov                 dword ptr [edi + 0x134], ebx
            //   899f74010000         | mov                 dword ptr [edi + 0x174], ebx
            //   899f70010000         | mov                 dword ptr [edi + 0x170], ebx
            //   8d877c010000         | lea                 eax, [edi + 0x17c]
            //   50                   | push                eax

        $sequence_3 = { 035018 3bf2 7205 e8???????? 85db 740a }
            // n = 6, score = 100
            //   035018               | add                 edx, dword ptr [eax + 0x18]
            //   3bf2                 | cmp                 esi, edx
            //   7205                 | jb                  7
            //   e8????????           |                     
            //   85db                 | test                ebx, ebx
            //   740a                 | je                  0xc

        $sequence_4 = { 730d 3bd3 7609 8bfe e8???????? eb0e 3bf3 }
            // n = 7, score = 100
            //   730d                 | jae                 0xf
            //   3bd3                 | cmp                 edx, ebx
            //   7609                 | jbe                 0xb
            //   8bfe                 | mov                 edi, esi
            //   e8????????           |                     
            //   eb0e                 | jmp                 0x10
            //   3bf3                 | cmp                 esi, ebx

        $sequence_5 = { 50 c78678010000385d6e00 ff15???????? 39ae6c010000 720f 8b8e58010000 51 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c78678010000385d6e00     | mov    dword ptr [esi + 0x178], 0x6e5d38
            //   ff15????????         |                     
            //   39ae6c010000         | cmp                 dword ptr [esi + 0x16c], ebp
            //   720f                 | jb                  0x11
            //   8b8e58010000         | mov                 ecx, dword ptr [esi + 0x158]
            //   51                   | push                ecx

        $sequence_6 = { e8???????? 83c404 8b4f18 8b5714 8b471c 51 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4f18               | mov                 ecx, dword ptr [edi + 0x18]
            //   8b5714               | mov                 edx, dword ptr [edi + 0x14]
            //   8b471c               | mov                 eax, dword ptr [edi + 0x1c]
            //   51                   | push                ecx

        $sequence_7 = { 7d10 8a8c181d010000 8888a0976e00 40 ebe6 ff35???????? }
            // n = 6, score = 100
            //   7d10                 | jge                 0x12
            //   8a8c181d010000       | mov                 cl, byte ptr [eax + ebx + 0x11d]
            //   8888a0976e00         | mov                 byte ptr [eax + 0x6e97a0], cl
            //   40                   | inc                 eax
            //   ebe6                 | jmp                 0xffffffe8
            //   ff35????????         |                     

        $sequence_8 = { 57 8b7e18 03c7 3bf8 7605 e8???????? 8b36 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8b7e18               | mov                 edi, dword ptr [esi + 0x18]
            //   03c7                 | add                 eax, edi
            //   3bf8                 | cmp                 edi, eax
            //   7605                 | jbe                 7
            //   e8????????           |                     
            //   8b36                 | mov                 esi, dword ptr [esi]

        $sequence_9 = { e9???????? 3bf3 0f84a6000000 6a28 e8???????? 83c404 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   3bf3                 | cmp                 esi, ebx
            //   0f84a6000000         | je                  0xac
            //   6a28                 | push                0x28
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 253952
}