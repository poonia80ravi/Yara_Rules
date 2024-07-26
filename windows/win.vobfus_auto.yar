rule win_vobfus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.vobfus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vobfus"
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
        $sequence_0 = { 8b5508 8b92e8000000 8b822c210000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b822c210000         | mov                 eax, dword ptr [edx + 0x212c]
            //   50                   | push                eax

        $sequence_1 = { 55 8bec 8b5508 8b92e8000000 8b8254200000 }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8254200000         | mov                 eax, dword ptr [edx + 0x2054]

        $sequence_2 = { 8b82880a0000 50 50 8b10 ff5204 }
            // n = 5, score = 200
            //   8b82880a0000         | mov                 eax, dword ptr [edx + 0xa88]
            //   50                   | push                eax
            //   50                   | push                eax
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5204               | call                dword ptr [edx + 4]

        $sequence_3 = { 8b5508 8b92e8000000 8b82c40d0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82c40d0000         | mov                 eax, dword ptr [edx + 0xdc4]
            //   50                   | push                eax

        $sequence_4 = { 8b5508 8b92e8000000 8b8248080000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8248080000         | mov                 eax, dword ptr [edx + 0x848]
            //   50                   | push                eax

        $sequence_5 = { 8b5508 8b92e8000000 8b821c130000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b821c130000         | mov                 eax, dword ptr [edx + 0x131c]
            //   50                   | push                eax

        $sequence_6 = { 8b5508 8b92e8000000 8b82a4030000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82a4030000         | mov                 eax, dword ptr [edx + 0x3a4]
            //   50                   | push                eax

        $sequence_7 = { 8b5508 8b92e8000000 8b82681b0000 50 50 }
            // n = 5, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82681b0000         | mov                 eax, dword ptr [edx + 0x1b68]
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_8 = { 14ff 0470 fe0a d6 }
            // n = 4, score = 100
            //   14ff                 | adc                 al, 0xff
            //   0470                 | add                 al, 0x70
            //   fe0a                 | dec                 byte ptr [edx]
            //   d6                   | salc                

        $sequence_9 = { f3ed ebf2 ed ec }
            // n = 4, score = 100
            //   f3ed                 | in                  eax, dx
            //   ebf2                 | jmp                 0xfffffff4
            //   ed                   | in                  eax, dx
            //   ec                   | in                  al, dx

        $sequence_10 = { d86f93 c8ed9459 ef 60 226aa3 60 8907 }
            // n = 7, score = 100
            //   d86f93               | fsubr               dword ptr [edi - 0x6d]
            //   c8ed9459             | enter               -0x6b13, 0x59
            //   ef                   | out                 dx, eax
            //   60                   | pushal              
            //   226aa3               | and                 ch, byte ptr [edx - 0x5d]
            //   60                   | pushal              
            //   8907                 | mov                 dword ptr [edi], eax

        $sequence_11 = { 5c f6ac4ff8b54ffb c058fcca 61 }
            // n = 4, score = 100
            //   5c                   | pop                 esp
            //   f6ac4ff8b54ffb       | imul                byte ptr [edi + ecx*2 - 0x4b04a08]
            //   c058fcca             | rcr                 byte ptr [eax - 4], 0xca
            //   61                   | popal               

        $sequence_12 = { 7a43 92 9afc9e5780451f 4a a1???????? 57 }
            // n = 6, score = 100
            //   7a43                 | jp                  0x45
            //   92                   | xchg                eax, edx
            //   9afc9e5780451f       | lcall               0x1f45:0x80579efc
            //   4a                   | dec                 edx
            //   a1????????           |                     
            //   57                   | push                edi

        $sequence_13 = { 0853ac 866cedad b909dfd18c 9d }
            // n = 4, score = 100
            //   0853ac               | or                  byte ptr [ebx - 0x54], dl
            //   866cedad             | xchg                byte ptr [ebp + ebp*8 - 0x53], ch
            //   b909dfd18c           | mov                 ecx, 0x8cd1df09
            //   9d                   | popfd               

        $sequence_14 = { 0d50004900 3e3cff 46 14ff }
            // n = 4, score = 100
            //   0d50004900           | or                  eax, 0x490050
            //   3e3cff               | cmp                 al, 0xff
            //   46                   | inc                 esi
            //   14ff                 | adc                 al, 0xff

        $sequence_15 = { ae 73f3 aa 5c f6ac4ff8b54ffb }
            // n = 5, score = 100
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   73f3                 | jae                 0xfffffff5
            //   aa                   | stosb               byte ptr es:[edi], al
            //   5c                   | pop                 esp
            //   f6ac4ff8b54ffb       | imul                byte ptr [edi + ecx*2 - 0x4b04a08]

        $sequence_16 = { 8f00 e3ce 97 00e6 d39500e4d19b }
            // n = 5, score = 100
            //   8f00                 | pop                 dword ptr [eax]
            //   e3ce                 | jecxz               0xffffffd0
            //   97                   | xchg                eax, edi
            //   00e6                 | add                 dh, ah
            //   d39500e4d19b         | rcl                 dword ptr [ebp - 0x642e1c00], cl

        $sequence_17 = { bbe94bd920 31cc bff21d4a0a 07 52 2db053f02c 0faa }
            // n = 7, score = 100
            //   bbe94bd920           | mov                 ebx, 0x20d94be9
            //   31cc                 | xor                 esp, ecx
            //   bff21d4a0a           | mov                 edi, 0xa4a1df2
            //   07                   | pop                 es
            //   52                   | push                edx
            //   2db053f02c           | sub                 eax, 0x2cf053b0
            //   0faa                 | rsm                 

        $sequence_18 = { 1400 48 0008 78ff }
            // n = 4, score = 100
            //   1400                 | adc                 al, 0
            //   48                   | dec                 eax
            //   0008                 | add                 byte ptr [eax], cl
            //   78ff                 | js                  1

        $sequence_19 = { de0d???????? f5 24c0 184002 }
            // n = 4, score = 100
            //   de0d????????         |                     
            //   f5                   | cmc                 
            //   24c0                 | and                 al, 0xc0
            //   184002               | sbb                 byte ptr [eax + 2], al

        $sequence_20 = { ec f2ed ec f2ed ec f2ed }
            // n = 6, score = 100
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx

        $sequence_21 = { 85783e d7 29ee 7ccb 59 }
            // n = 5, score = 100
            //   85783e               | test                dword ptr [eax + 0x3e], edi
            //   d7                   | xlatb               
            //   29ee                 | sub                 esi, ebp
            //   7ccb                 | jl                  0xffffffcd
            //   59                   | pop                 ecx

        $sequence_22 = { 49 e278 8161d356b32dee 57 7df8 ab }
            // n = 6, score = 100
            //   49                   | dec                 ecx
            //   e278                 | loop                0x7a
            //   8161d356b32dee       | and                 dword ptr [ecx - 0x2d], 0xee2db356
            //   57                   | push                edi
            //   7df8                 | jge                 0xfffffffa
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_23 = { f2ed ec f3ed ebf2 }
            // n = 4, score = 100
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f3ed                 | in                  eax, dx
            //   ebf2                 | jmp                 0xfffffff4

    condition:
        7 of them and filesize < 409600
}