rule win_webmonitor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webmonitor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webmonitor"
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
        $sequence_0 = { 9e 0808 008a30019ef5 0000 00c0 }
            // n = 5, score = 200
            //   9e                   | sahf                
            //   0808                 | or                  byte ptr [eax], cl
            //   008a30019ef5         | add                 byte ptr [edx - 0xa61fed0], cl
            //   0000                 | add                 byte ptr [eax], al
            //   00c0                 | add                 al, al

        $sequence_1 = { fa 41 0014b4 42 }
            // n = 4, score = 200
            //   fa                   | cli                 
            //   41                   | inc                 ecx
            //   0014b4               | add                 byte ptr [esp + esi*4], dl
            //   42                   | inc                 edx

        $sequence_2 = { 000d???????? 04b8 fe04e4 fd 04e0 }
            // n = 5, score = 200
            //   000d????????         |                     
            //   04b8                 | add                 al, 0xb8
            //   fe04e4               | inc                 byte ptr [esp]
            //   fd                   | std                 
            //   04e0                 | add                 al, 0xe0

        $sequence_3 = { a4 44 43 00dc 7442 000477 }
            // n = 6, score = 200
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   44                   | inc                 esp
            //   43                   | inc                 ebx
            //   00dc                 | add                 ah, bl
            //   7442                 | je                  0x44
            //   000477               | add                 byte ptr [edi + esi*2], al

        $sequence_4 = { fd 0512002413 000d???????? 04e4 fd }
            // n = 5, score = 200
            //   fd                   | std                 
            //   0512002413           | add                 eax, 0x13240012
            //   000d????????         |                     
            //   04e4                 | add                 al, 0xe4
            //   fd                   | std                 

        $sequence_5 = { 0080cd41009c d34100 e8???????? a3???????? 41 00f4 }
            // n = 6, score = 200
            //   0080cd41009c         | add                 byte ptr [eax - 0x63ffbe33], al
            //   d34100               | rol                 dword ptr [ecx], cl
            //   e8????????           |                     
            //   a3????????           |                     
            //   41                   | inc                 ecx
            //   00f4                 | add                 ah, dh

        $sequence_6 = { 000b 3a58ff 1b03 fd }
            // n = 4, score = 200
            //   000b                 | add                 byte ptr [ebx], cl
            //   3a58ff               | cmp                 bl, byte ptr [eax - 1]
            //   1b03                 | sbb                 eax, dword ptr [ebx]
            //   fd                   | std                 

        $sequence_7 = { 04c8 fe04fc fd 04f8 fd ff01 04f8 }
            // n = 7, score = 200
            //   04c8                 | add                 al, 0xc8
            //   fe04fc               | inc                 byte ptr [esp + edi*8]
            //   fd                   | std                 
            //   04f8                 | add                 al, 0xf8
            //   fd                   | std                 
            //   ff01                 | inc                 dword ptr [ecx]
            //   04f8                 | add                 al, 0xf8

        $sequence_8 = { 00e8 dd7000 008bf98b5d1c 8d4de4 }
            // n = 4, score = 100
            //   00e8                 | add                 al, ch
            //   dd7000               | fnsave              dword ptr [eax]
            //   008bf98b5d1c         | add                 byte ptr [ebx + 0x1c5d8bf9], cl
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_9 = { 0108 eb5a 8b4508 83ceff }
            // n = 4, score = 100
            //   0108                 | add                 dword ptr [eax], ecx
            //   eb5a                 | jmp                 0x5c
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83ceff               | or                  esi, 0xffffffff

        $sequence_10 = { 0108 8b442410 891e 894604 }
            // n = 4, score = 100
            //   0108                 | add                 dword ptr [eax], ecx
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   891e                 | mov                 dword ptr [esi], ebx
            //   894604               | mov                 dword ptr [esi + 4], eax

        $sequence_11 = { 00d1 6848004069 48 00d1 }
            // n = 4, score = 100
            //   00d1                 | add                 cl, dl
            //   6848004069           | push                0x69400048
            //   48                   | dec                 eax
            //   00d1                 | add                 cl, dl

        $sequence_12 = { 00e8 f61c00 008bd9895df0 8b451c }
            // n = 4, score = 100
            //   00e8                 | add                 al, ch
            //   f61c00               | neg                 byte ptr [eax + eax]
            //   008bd9895df0         | add                 byte ptr [ebx - 0xfa27627], cl
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]

        $sequence_13 = { 000f b681 fc b84500ff24 }
            // n = 4, score = 100
            //   000f                 | add                 byte ptr [edi], cl
            //   b681                 | mov                 dh, 0x81
            //   fc                   | cld                 
            //   b84500ff24           | mov                 eax, 0x24ff0045

        $sequence_14 = { 00d1 6848007269 48 00856948008b }
            // n = 4, score = 100
            //   00d1                 | add                 cl, dl
            //   6848007269           | push                0x69720048
            //   48                   | dec                 eax
            //   00856948008b         | add                 byte ptr [ebp - 0x74ffb797], al

        $sequence_15 = { 00856948008b ff558b ec 83ec0c }
            // n = 4, score = 100
            //   00856948008b         | add                 byte ptr [ebp - 0x74ffb797], al
            //   ff558b               | call                dword ptr [ebp - 0x75]
            //   ec                   | in                  al, dx
            //   83ec0c               | sub                 esp, 0xc

    condition:
        7 of them and filesize < 1867776
}