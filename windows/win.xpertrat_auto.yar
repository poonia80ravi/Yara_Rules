rule win_xpertrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.xpertrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xpertrat"
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
        $sequence_0 = { 250004003c 6c 70ff 0808 }
            // n = 4, score = 200
            //   250004003c           | and                 eax, 0x3c000400
            //   6c                   | insb                byte ptr es:[edi], dx
            //   70ff                 | jo                  1
            //   0808                 | or                  byte ptr [eax], cl

        $sequence_1 = { 0870ff 0d80000700 0474 ff0478 ff05???????? 000d???????? 0878ff }
            // n = 7, score = 200
            //   0870ff               | or                  byte ptr [eax - 1], dh
            //   0d80000700           | or                  eax, 0x70080
            //   0474                 | add                 al, 0x74
            //   ff0478               | inc                 dword ptr [eax + edi*2]
            //   ff05????????         |                     
            //   000d????????         |                     
            //   0878ff               | or                  byte ptr [eax - 1], bh

        $sequence_2 = { 001b 0d002a2364 ff08 0800 }
            // n = 4, score = 200
            //   001b                 | add                 byte ptr [ebx], bl
            //   0d002a2364           | or                  eax, 0x64232a00
            //   ff08                 | dec                 dword ptr [eax]
            //   0800                 | or                  byte ptr [eax], al

        $sequence_3 = { 008a3800cc1c 5e 006c70ff 0808 }
            // n = 4, score = 200
            //   008a3800cc1c         | add                 byte ptr [edx + 0x1ccc0038], cl
            //   5e                   | pop                 esi
            //   006c70ff             | add                 byte ptr [eax + esi*2 - 1], ch
            //   0808                 | or                  byte ptr [eax], cl

        $sequence_4 = { 045c ff4d40 ff08 40 }
            // n = 4, score = 200
            //   045c                 | add                 al, 0x5c
            //   ff4d40               | dec                 dword ptr [ebp + 0x40]
            //   ff08                 | dec                 dword ptr [eax]
            //   40                   | inc                 eax

        $sequence_5 = { ff05???????? 000d???????? 0878ff 0d98000700 6e 74ff }
            // n = 6, score = 200
            //   ff05????????         |                     
            //   000d????????         |                     
            //   0878ff               | or                  byte ptr [eax - 1], bh
            //   0d98000700           | or                  eax, 0x70098
            //   6e                   | outsb               dx, byte ptr [esi]
            //   74ff                 | je                  1

        $sequence_6 = { ff08 40 0430 ff0a 4c 000c00 }
            // n = 6, score = 200
            //   ff08                 | dec                 dword ptr [eax]
            //   40                   | inc                 eax
            //   0430                 | add                 al, 0x30
            //   ff0a                 | dec                 dword ptr [edx]
            //   4c                   | dec                 esp
            //   000c00               | add                 byte ptr [eax + eax], cl

        $sequence_7 = { 007168 ff0468 ff0a 250004003c 6c }
            // n = 5, score = 200
            //   007168               | add                 byte ptr [ecx + 0x68], dh
            //   ff0468               | inc                 dword ptr [eax + ebp*2]
            //   ff0a                 | dec                 dword ptr [edx]
            //   250004003c           | and                 eax, 0x3c000400
            //   6c                   | insb                byte ptr es:[edi], dx

        $sequence_8 = { eb12 8b55dc 039504feffff 0f80af530000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   039504feffff         | add                 edx, dword ptr [ebp - 0x1fc]
            //   0f80af530000         | jo                  0x53b5

        $sequence_9 = { eb12 8b4ddc 038d68ffffff 0f80cf030000 894ddc 8b55dc 3b9564ffffff }
            // n = 7, score = 100
            //   eb12                 | jmp                 0x14
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   038d68ffffff         | add                 ecx, dword ptr [ebp - 0x98]
            //   0f80cf030000         | jo                  0x3d5
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   3b9564ffffff         | cmp                 edx, dword ptr [ebp - 0x9c]

        $sequence_10 = { eb12 8b4ddc 038dccfdffff 0f80ba120000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   038dccfdffff         | add                 ecx, dword ptr [ebp - 0x234]
            //   0f80ba120000         | jo                  0x12c0

        $sequence_11 = { eb12 8b4ddc 038db4feffff 0f80850f0000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   038db4feffff         | add                 ecx, dword ptr [ebp - 0x14c]
            //   0f80850f0000         | jo                  0xf8b

        $sequence_12 = { eb12 8b4ddc 038dd4fdffff 0f80391a0000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   038dd4fdffff         | add                 ecx, dword ptr [ebp - 0x22c]
            //   0f80391a0000         | jo                  0x1a3f

        $sequence_13 = { eb12 8b4ddc 038dd8feffff 0f8041030000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   038dd8feffff         | add                 ecx, dword ptr [ebp - 0x128]
            //   0f8041030000         | jo                  0x347

        $sequence_14 = { eb12 8b4ddc 038d70ffffff 0f804f070000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   038d70ffffff         | add                 ecx, dword ptr [ebp - 0x90]
            //   0f804f070000         | jo                  0x755

        $sequence_15 = { eb12 8b55dc 039538ffffff 0f8041030000 }
            // n = 4, score = 100
            //   eb12                 | jmp                 0x14
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   039538ffffff         | add                 edx, dword ptr [ebp - 0xc8]
            //   0f8041030000         | jo                  0x347

    condition:
        7 of them and filesize < 8560640
}