rule win_parasite_http_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.parasite_http."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parasite_http"
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
        $sequence_0 = { 6a02 8d45f0 50 53 53 53 8d45f8 }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_1 = { 752d 50 52 81f290000000 52 81ea80000000 }
            // n = 6, score = 100
            //   752d                 | jne                 0x2f
            //   50                   | push                eax
            //   52                   | push                edx
            //   81f290000000         | xor                 edx, 0x90
            //   52                   | push                edx
            //   81ea80000000         | sub                 edx, 0x80

        $sequence_2 = { 53 56 8365d400 8365d800 8365f800 8365f400 8365f000 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8365d400             | and                 dword ptr [ebp - 0x2c], 0
            //   8365d800             | and                 dword ptr [ebp - 0x28], 0
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8365f400             | and                 dword ptr [ebp - 0xc], 0
            //   8365f000             | and                 dword ptr [ebp - 0x10], 0

        $sequence_3 = { 51 8d8dccf3ffff 51 57 53 ffd0 85c0 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d8dccf3ffff         | lea                 ecx, [ebp - 0xc34]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_4 = { 7434 8bde 85f6 7428 83ef02 6a0a 8d0477 }
            // n = 7, score = 100
            //   7434                 | je                  0x36
            //   8bde                 | mov                 ebx, esi
            //   85f6                 | test                esi, esi
            //   7428                 | je                  0x2a
            //   83ef02               | sub                 edi, 2
            //   6a0a                 | push                0xa
            //   8d0477               | lea                 eax, [edi + esi*2]

        $sequence_5 = { c745d4321f4000 c745d8661f4000 c745dc961f4000 c745e0d61f4000 c745e416204000 c745e856204000 c745ec9e204000 }
            // n = 7, score = 100
            //   c745d4321f4000       | mov                 dword ptr [ebp - 0x2c], 0x401f32
            //   c745d8661f4000       | mov                 dword ptr [ebp - 0x28], 0x401f66
            //   c745dc961f4000       | mov                 dword ptr [ebp - 0x24], 0x401f96
            //   c745e0d61f4000       | mov                 dword ptr [ebp - 0x20], 0x401fd6
            //   c745e416204000       | mov                 dword ptr [ebp - 0x1c], 0x402016
            //   c745e856204000       | mov                 dword ptr [ebp - 0x18], 0x402056
            //   c745ec9e204000       | mov                 dword ptr [ebp - 0x14], 0x40209e

        $sequence_6 = { 5b 5d c20c00 53 56 8bd9 b9???????? }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bd9                 | mov                 ebx, ecx
            //   b9????????           |                     

        $sequence_7 = { 40 5f 5e c3 56 57 be???????? }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   57                   | push                edi
            //   be????????           |                     

        $sequence_8 = { 83c006 50 56 ffd3 8bc7 5f }
            // n = 6, score = 100
            //   83c006               | add                 eax, 6
            //   50                   | push                eax
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi

        $sequence_9 = { 53 56 57 6a10 8bf9 33db 5e }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a10                 | push                0x10
            //   8bf9                 | mov                 edi, ecx
            //   33db                 | xor                 ebx, ebx
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 147456
}