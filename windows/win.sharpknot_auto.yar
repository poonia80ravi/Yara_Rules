rule win_sharpknot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sharpknot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sharpknot"
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
        $sequence_0 = { 8d4c2468 51 e8???????? 83c408 3bc3 7403 }
            // n = 6, score = 100
            //   8d4c2468             | lea                 ecx, [esp + 0x68]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   3bc3                 | cmp                 eax, ebx
            //   7403                 | je                  5

        $sequence_1 = { ff15???????? 50 e8???????? 83c404 85c0 7429 8d842454020000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7429                 | je                  0x2b
            //   8d842454020000       | lea                 eax, [esp + 0x254]

        $sequence_2 = { 68???????? 57 57 ff15???????? 8bf0 ff15???????? }
            // n = 6, score = 100
            //   68????????           |                     
            //   57                   | push                edi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     

        $sequence_3 = { 8bd8 0f8494000000 85db 0f848c000000 }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   0f8494000000         | je                  0x9a
            //   85db                 | test                ebx, ebx
            //   0f848c000000         | je                  0x92

        $sequence_4 = { 33c0 eb05 1bc0 83d8ff 85c0 7470 8d44243c }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   eb05                 | jmp                 7
            //   1bc0                 | sbb                 eax, eax
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   7470                 | je                  0x72
            //   8d44243c             | lea                 eax, [esp + 0x3c]

        $sequence_5 = { 7358 8bc1 c1f805 8d3c8540e64400 8bc1 }
            // n = 5, score = 100
            //   7358                 | jae                 0x5a
            //   8bc1                 | mov                 eax, ecx
            //   c1f805               | sar                 eax, 5
            //   8d3c8540e64400       | lea                 edi, [eax*4 + 0x44e640]
            //   8bc1                 | mov                 eax, ecx

        $sequence_6 = { 8bc8 83e01f c1f905 8d34c0 8b048d40e64400 }
            // n = 5, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8d34c0               | lea                 esi, [eax + eax*8]
            //   8b048d40e64400       | mov                 eax, dword ptr [ecx*4 + 0x44e640]

        $sequence_7 = { e8???????? 83c404 8bf0 8b4304 8bcb }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bf0                 | mov                 esi, eax
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_8 = { 33c0 8d7c2421 88542420 f3ab 66ab 33c9 aa }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8d7c2421             | lea                 edi, [esp + 0x21]
            //   88542420             | mov                 byte ptr [esp + 0x20], dl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   33c9                 | xor                 ecx, ecx
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_9 = { 0fb6c3 f68081f8440004 741a 8a4601 46 84c0 741d }
            // n = 7, score = 100
            //   0fb6c3               | movzx               eax, bl
            //   f68081f8440004       | test                byte ptr [eax + 0x44f881], 4
            //   741a                 | je                  0x1c
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   46                   | inc                 esi
            //   84c0                 | test                al, al
            //   741d                 | je                  0x1f

    condition:
        7 of them and filesize < 1032192
}