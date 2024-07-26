rule win_sisfader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sisfader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sisfader"
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
        $sequence_0 = { e8???????? 85c0 b91d000000 0f44d9 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   b91d000000           | mov                 ecx, 0x1d
            //   0f44d9               | cmove               ebx, ecx

        $sequence_1 = { 85c9 741f 33c0 85c9 }
            // n = 4, score = 300
            //   85c9                 | test                ecx, ecx
            //   741f                 | je                  0x21
            //   33c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx

        $sequence_2 = { 85c0 7e08 03d8 3bdf 7c98 eb06 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   7e08                 | jle                 0xa
            //   03d8                 | add                 ebx, eax
            //   3bdf                 | cmp                 ebx, edi
            //   7c98                 | jl                  0xffffff9a
            //   eb06                 | jmp                 8

        $sequence_3 = { 8b442470 89442438 8b44246c 8944243c }
            // n = 4, score = 200
            //   8b442470             | mov                 eax, dword ptr [esp + 0x70]
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   8b44246c             | mov                 eax, dword ptr [esp + 0x6c]
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax

        $sequence_4 = { 8bec 83ec60 c745fc00000000 c745e000000000 6a40 }
            // n = 5, score = 200
            //   8bec                 | mov                 ebp, esp
            //   83ec60               | sub                 esp, 0x60
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0
            //   6a40                 | push                0x40

        $sequence_5 = { 52 ff15???????? 8945f8 837df800 7402 eb5b }
            // n = 6, score = 200
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7402                 | je                  4
            //   eb5b                 | jmp                 0x5d

        $sequence_6 = { 81fb00000200 740c 3b1e 743d 85db 7508 891e }
            // n = 7, score = 200
            //   81fb00000200         | cmp                 ebx, 0x20000
            //   740c                 | je                  0xe
            //   3b1e                 | cmp                 ebx, dword ptr [esi]
            //   743d                 | je                  0x3f
            //   85db                 | test                ebx, ebx
            //   7508                 | jne                 0xa
            //   891e                 | mov                 dword ptr [esi], ebx

        $sequence_7 = { 8b4508 a3???????? c705????????07000000 8b4d0c }
            // n = 4, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   a3????????           |                     
            //   c705????????07000000     |     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_8 = { 8945c4 837dc400 750d 685a040000 }
            // n = 4, score = 200
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   837dc400             | cmp                 dword ptr [ebp - 0x3c], 0
            //   750d                 | jne                 0xf
            //   685a040000           | push                0x45a

        $sequence_9 = { 57 ff15???????? 85db 751a 8b4d14 8bd6 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85db                 | test                ebx, ebx
            //   751a                 | jne                 0x1c
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8bd6                 | mov                 edx, esi

        $sequence_10 = { 8b4c240c 03f0 53 ff7514 }
            // n = 4, score = 200
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   03f0                 | add                 esi, eax
            //   53                   | push                ebx
            //   ff7514               | push                dword ptr [ebp + 0x14]

        $sequence_11 = { b90e000000 ff15???????? 33c0 e9???????? e9???????? ff15???????? }
            // n = 6, score = 200
            //   b90e000000           | mov                 ecx, 0xe
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   e9????????           |                     
            //   ff15????????         |                     

        $sequence_12 = { c705????????00000000 8b442440 8905???????? c705????????b80b0000 }
            // n = 4, score = 200
            //   c705????????00000000     |     
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]
            //   8905????????         |                     
            //   c705????????b80b0000     |     

        $sequence_13 = { 8b45d8 894214 8b4dfc 8b5510 }
            // n = 4, score = 200
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   894214               | mov                 dword ptr [edx + 0x14], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]

        $sequence_14 = { e8???????? 8b442470 c74708e2e00000 0f1005???????? 894704 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   8b442470             | mov                 eax, dword ptr [esp + 0x70]
            //   c74708e2e00000       | mov                 dword ptr [edi + 8], 0xe0e2
            //   0f1005????????       |                     
            //   894704               | mov                 dword ptr [edi + 4], eax

        $sequence_15 = { 8b4dfc 8b5108 52 ff15???????? 83c404 8b45fc }
            // n = 6, score = 200
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_16 = { 8b4d0c 894dec 8b55ec 8b02 8945f4 8b4de8 }
            // n = 6, score = 200
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]

        $sequence_17 = { 89442450 837c245000 7405 e9???????? 83bc248000000000 }
            // n = 5, score = 200
            //   89442450             | mov                 dword ptr [esp + 0x50], eax
            //   837c245000           | cmp                 dword ptr [esp + 0x50], 0
            //   7405                 | je                  7
            //   e9????????           |                     
            //   83bc248000000000     | cmp                 dword ptr [esp + 0x80], 0

        $sequence_18 = { 57 6a68 ff15???????? c1e802 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   6a68                 | push                0x68
            //   ff15????????         |                     
            //   c1e802               | shr                 eax, 2

        $sequence_19 = { eb0f c745f001000000 33c0 0f8579ffffff 837dfc00 }
            // n = 5, score = 200
            //   eb0f                 | jmp                 0x11
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   33c0                 | xor                 eax, eax
            //   0f8579ffffff         | jne                 0xffffff7f
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0

        $sequence_20 = { 6a00 ffd1 5e 33c0 5b }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   ffd1                 | call                ecx
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx

        $sequence_21 = { 0f852b010000 81790418020000 7413 b818000000 }
            // n = 4, score = 200
            //   0f852b010000         | jne                 0x131
            //   81790418020000       | cmp                 dword ptr [ecx + 4], 0x218
            //   7413                 | je                  0x15
            //   b818000000           | mov                 eax, 0x18

        $sequence_22 = { 89442420 837c242001 7402 eb05 }
            // n = 4, score = 200
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   837c242001           | cmp                 dword ptr [esp + 0x20], 1
            //   7402                 | je                  4
            //   eb05                 | jmp                 7

        $sequence_23 = { 837c242003 745d 837c242004 7479 837c242005 }
            // n = 5, score = 200
            //   837c242003           | cmp                 dword ptr [esp + 0x20], 3
            //   745d                 | je                  0x5f
            //   837c242004           | cmp                 dword ptr [esp + 0x20], 4
            //   7479                 | je                  0x7b
            //   837c242005           | cmp                 dword ptr [esp + 0x20], 5

        $sequence_24 = { 8b442440 89442420 837c242001 7425 837c242002 7441 }
            // n = 6, score = 200
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   837c242001           | cmp                 dword ptr [esp + 0x20], 1
            //   7425                 | je                  0x27
            //   837c242002           | cmp                 dword ptr [esp + 0x20], 2
            //   7441                 | je                  0x43

        $sequence_25 = { 8b8db0fdffff 894744 8d85c0fdffff 50 56 }
            // n = 5, score = 200
            //   8b8db0fdffff         | mov                 ecx, dword ptr [ebp - 0x250]
            //   894744               | mov                 dword ptr [edi + 0x44], eax
            //   8d85c0fdffff         | lea                 eax, [ebp - 0x240]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_26 = { 8b442438 8905???????? c705????????00000000 8b442440 }
            // n = 4, score = 200
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   8905????????         |                     
            //   c705????????00000000     |     
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]

        $sequence_27 = { c3 81f9e2f00000 756b c74708e3f00000 }
            // n = 4, score = 200
            //   c3                   | ret                 
            //   81f9e2f00000         | cmp                 ecx, 0xf0e2
            //   756b                 | jne                 0x6d
            //   c74708e3f00000       | mov                 dword ptr [edi + 8], 0xf0e3

        $sequence_28 = { 746b c744242000000000 eb0a 8b442420 ffc0 }
            // n = 5, score = 200
            //   746b                 | je                  0x6d
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   eb0a                 | jmp                 0xc
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   ffc0                 | inc                 eax

        $sequence_29 = { 8d5204 884afb 0fb6480d 3248fd 884afc 0fb6480e 3248fe }
            // n = 7, score = 200
            //   8d5204               | lea                 edx, [edx + 4]
            //   884afb               | mov                 byte ptr [edx - 5], cl
            //   0fb6480d             | movzx               ecx, byte ptr [eax + 0xd]
            //   3248fd               | xor                 cl, byte ptr [eax - 3]
            //   884afc               | mov                 byte ptr [edx - 4], cl
            //   0fb6480e             | movzx               ecx, byte ptr [eax + 0xe]
            //   3248fe               | xor                 cl, byte ptr [eax - 2]

    condition:
        7 of them and filesize < 417792
}