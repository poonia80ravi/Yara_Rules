rule win_nestegg_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.nestegg."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nestegg"
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
        $sequence_0 = { 8d7c2415 c644241400 f3ab 8bb42418040000 6a04 66ab aa }
            // n = 7, score = 200
            //   8d7c2415             | lea                 edi, [esp + 0x15]
            //   c644241400           | mov                 byte ptr [esp + 0x14], 0
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8bb42418040000       | mov                 esi, dword ptr [esp + 0x418]
            //   6a04                 | push                4
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_1 = { 8b1c95241e4100 8b56fc 33c3 8b1c8d242a4100 33c3 }
            // n = 5, score = 200
            //   8b1c95241e4100       | mov                 ebx, dword ptr [edx*4 + 0x411e24]
            //   8b56fc               | mov                 edx, dword ptr [esi - 4]
            //   33c3                 | xor                 eax, ebx
            //   8b1c8d242a4100       | mov                 ebx, dword ptr [ecx*4 + 0x412a24]
            //   33c3                 | xor                 eax, ebx

        $sequence_2 = { 8944240f 56 57 33db 8944241b b940000000 8d7c2479 }
            // n = 7, score = 200
            //   8944240f             | mov                 dword ptr [esp + 0xf], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   8944241b             | mov                 dword ptr [esp + 0x1b], eax
            //   b940000000           | mov                 ecx, 0x40
            //   8d7c2479             | lea                 edi, [esp + 0x79]

        $sequence_3 = { 33c0 53 8944240f 56 57 33db }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   53                   | push                ebx
            //   8944240f             | mov                 dword ptr [esp + 0xf], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx

        $sequence_4 = { c744241000000000 ffd7 83c404 48 8944240c 8a8610030000 }
            // n = 6, score = 200
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   ffd7                 | call                edi
            //   83c404               | add                 esp, 4
            //   48                   | dec                 eax
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   8a8610030000         | mov                 al, byte ptr [esi + 0x310]

        $sequence_5 = { c3 6a00 ffd3 8b4f20 83c404 33d2 3bc8 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   6a00                 | push                0
            //   ffd3                 | call                ebx
            //   8b4f20               | mov                 ecx, dword ptr [edi + 0x20]
            //   83c404               | add                 esp, 4
            //   33d2                 | xor                 edx, edx
            //   3bc8                 | cmp                 ecx, eax

        $sequence_6 = { 7516 8bce 89460c e8???????? 8bce e8???????? }
            // n = 6, score = 200
            //   7516                 | jne                 0x18
            //   8bce                 | mov                 ecx, esi
            //   89460c               | mov                 dword ptr [esi + 0xc], eax
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_7 = { 8bce e8???????? 89442410 a0???????? b943000000 88842494010000 }
            // n = 6, score = 200
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   a0????????           |                     
            //   b943000000           | mov                 ecx, 0x43
            //   88842494010000       | mov                 byte ptr [esp + 0x194], al

        $sequence_8 = { 8d4c2410 6a04 51 8bce c7442418ff020001 e8???????? 8d5710 }
            // n = 7, score = 200
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   6a04                 | push                4
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   c7442418ff020001     | mov                 dword ptr [esp + 0x18], 0x10002ff
            //   e8????????           |                     
            //   8d5710               | lea                 edx, [edi + 0x10]

        $sequence_9 = { 8844241d 8844241e 8d442408 b132 b264 50 c644240c77 }
            // n = 7, score = 200
            //   8844241d             | mov                 byte ptr [esp + 0x1d], al
            //   8844241e             | mov                 byte ptr [esp + 0x1e], al
            //   8d442408             | lea                 eax, [esp + 8]
            //   b132                 | mov                 cl, 0x32
            //   b264                 | mov                 dl, 0x64
            //   50                   | push                eax
            //   c644240c77           | mov                 byte ptr [esp + 0xc], 0x77

    condition:
        7 of them and filesize < 221184
}