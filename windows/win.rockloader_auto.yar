rule win_rockloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.rockloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rockloader"
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
        $sequence_0 = { 53 84c0 0f844f010000 3c5c 7407 8806 }
            // n = 6, score = 300
            //   53                   | push                ebx
            //   84c0                 | test                al, al
            //   0f844f010000         | je                  0x155
            //   3c5c                 | cmp                 al, 0x5c
            //   7407                 | je                  9
            //   8806                 | mov                 byte ptr [esi], al

        $sequence_1 = { ff7508 e8???????? eb15 8935???????? e9???????? ff7508 }
            // n = 6, score = 300
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   eb15                 | jmp                 0x17
            //   8935????????         |                     
            //   e9????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_2 = { 8345fc05 46 8a1e 84db 75d4 8b45fc 8b750c }
            // n = 7, score = 300
            //   8345fc05             | add                 dword ptr [ebp - 4], 5
            //   46                   | inc                 esi
            //   8a1e                 | mov                 bl, byte ptr [esi]
            //   84db                 | test                bl, bl
            //   75d4                 | jne                 0xffffffd6
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]

        $sequence_3 = { 5e 8be5 5d c21000 80385b 56 }
            // n = 6, score = 300
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   80385b               | cmp                 byte ptr [eax], 0x5b
            //   56                   | push                esi

        $sequence_4 = { 8b7df4 8d4d0c 51 57 2bc6 8b7508 }
            // n = 6, score = 300
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   8d4d0c               | lea                 ecx, [ebp + 0xc]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   2bc6                 | sub                 eax, esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_5 = { 2175f8 8bf8 3975f4 7e55 53 8b45f8 }
            // n = 6, score = 300
            //   2175f8               | and                 dword ptr [ebp - 8], esi
            //   8bf8                 | mov                 edi, eax
            //   3975f4               | cmp                 dword ptr [ebp - 0xc], esi
            //   7e55                 | jle                 0x57
            //   53                   | push                ebx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_6 = { e8???????? 8b45fc 897d0c 8d7001 8a08 40 84c9 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   897d0c               | mov                 dword ptr [ebp + 0xc], edi
            //   8d7001               | lea                 esi, [eax + 1]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl

        $sequence_7 = { ff15???????? 8bf0 85f6 740a 6a28 6a00 56 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   740a                 | je                  0xc
            //   6a28                 | push                0x28
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_8 = { 3b75f4 7ce9 ff75f8 ff15???????? }
            // n = 4, score = 300
            //   3b75f4               | cmp                 esi, dword ptr [ebp - 0xc]
            //   7ce9                 | jl                  0xffffffeb
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_9 = { 59 81fb80000000 7305 33c9 41 eb17 81fb00080000 }
            // n = 7, score = 300
            //   59                   | pop                 ecx
            //   81fb80000000         | cmp                 ebx, 0x80
            //   7305                 | jae                 7
            //   33c9                 | xor                 ecx, ecx
            //   41                   | inc                 ecx
            //   eb17                 | jmp                 0x19
            //   81fb00080000         | cmp                 ebx, 0x800

    condition:
        7 of them and filesize < 98304
}