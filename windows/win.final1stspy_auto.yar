rule win_final1stspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.final1stspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.final1stspy"
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
        $sequence_0 = { b9???????? c1e006 8a7201 8ad3 3ad6 7412 }
            // n = 6, score = 300
            //   b9????????           |                     
            //   c1e006               | shl                 eax, 6
            //   8a7201               | mov                 dh, byte ptr [edx + 1]
            //   8ad3                 | mov                 dl, bl
            //   3ad6                 | cmp                 dl, dh
            //   7412                 | je                  0x14

        $sequence_1 = { 8a7201 8ad3 3ad6 7412 8a5101 41 84d2 }
            // n = 7, score = 300
            //   8a7201               | mov                 dh, byte ptr [edx + 1]
            //   8ad3                 | mov                 dl, bl
            //   3ad6                 | cmp                 dl, dh
            //   7412                 | je                  0x14
            //   8a5101               | mov                 dl, byte ptr [ecx + 1]
            //   41                   | inc                 ecx
            //   84d2                 | test                dl, dl

        $sequence_2 = { 8b45f8 2bf0 56 50 e8???????? }
            // n = 5, score = 300
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   2bf0                 | sub                 esi, eax
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { e8???????? 46 3bf7 7cf6 8b3d???????? be00020000 6810270000 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   46                   | inc                 esi
            //   3bf7                 | cmp                 esi, edi
            //   7cf6                 | jl                  0xfffffff8
            //   8b3d????????         |                     
            //   be00020000           | mov                 esi, 0x200
            //   6810270000           | push                0x2710

        $sequence_4 = { 7519 b8???????? 84db 7410 }
            // n = 4, score = 300
            //   7519                 | jne                 0x1b
            //   b8????????           |                     
            //   84db                 | test                bl, bl
            //   7410                 | je                  0x12

        $sequence_5 = { 03d0 8bc2 c1f810 8806 46 8a1d???????? 83ff02 }
            // n = 7, score = 300
            //   03d0                 | add                 edx, eax
            //   8bc2                 | mov                 eax, edx
            //   c1f810               | sar                 eax, 0x10
            //   8806                 | mov                 byte ptr [esi], al
            //   46                   | inc                 esi
            //   8a1d????????         |                     
            //   83ff02               | cmp                 edi, 2

        $sequence_6 = { e8???????? 8bf0 33c9 85f6 7e70 57 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   33c9                 | xor                 ecx, ecx
            //   85f6                 | test                esi, esi
            //   7e70                 | jle                 0x72
            //   57                   | push                edi

        $sequence_7 = { 5d c3 2d???????? 0f886cffffff 03d0 8bc2 c1f810 }
            // n = 7, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   2d????????           |                     
            //   0f886cffffff         | js                  0xffffff72
            //   03d0                 | add                 edx, eax
            //   8bc2                 | mov                 eax, edx
            //   c1f810               | sar                 eax, 0x10

        $sequence_8 = { 8a11 8acb 3aca 7425 8a4801 40 }
            // n = 6, score = 300
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   8acb                 | mov                 cl, bl
            //   3aca                 | cmp                 cl, dl
            //   7425                 | je                  0x27
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   40                   | inc                 eax

        $sequence_9 = { 8bc1 8955f4 56 8bf0 8945fc 57 }
            // n = 6, score = 300
            //   8bc1                 | mov                 eax, ecx
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   57                   | push                edi

    condition:
        7 of them and filesize < 557056
}