rule win_ddkeylogger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ddkeylogger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ddkeylogger"
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
        $sequence_0 = { 894814 8b4508 e8???????? 8b4df8 014d0c 014508 0145fc }
            // n = 7, score = 200
            //   894814               | mov                 dword ptr [eax + 0x14], ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   014d0c               | add                 dword ptr [ebp + 0xc], ecx
            //   014508               | add                 dword ptr [ebp + 8], eax
            //   0145fc               | add                 dword ptr [ebp - 4], eax

        $sequence_1 = { 40 84c9 75ee 8d85f0fdffff 8bf0 8d9b00000000 8a08 }
            // n = 7, score = 200
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75ee                 | jne                 0xfffffff0
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   8bf0                 | mov                 esi, eax
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   8a08                 | mov                 cl, byte ptr [eax]

        $sequence_2 = { 7229 f3a5 ff2495c0944000 8bc7 ba03000000 83e904 720c }
            // n = 7, score = 200
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff2495c0944000       | jmp                 dword ptr [edx*4 + 0x4094c0]
            //   8bc7                 | mov                 eax, edi
            //   ba03000000           | mov                 edx, 3
            //   83e904               | sub                 ecx, 4
            //   720c                 | jb                  0xe

        $sequence_3 = { 8845f1 8b55f4 8bc6 8d4d08 e8???????? 8b45f4 }
            // n = 6, score = 200
            //   8845f1               | mov                 byte ptr [ebp - 0xf], al
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8bc6                 | mov                 eax, esi
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_4 = { 49 b801000000 2945fc 75dd 2945f8 75d1 5f }
            // n = 7, score = 200
            //   49                   | dec                 ecx
            //   b801000000           | mov                 eax, 1
            //   2945fc               | sub                 dword ptr [ebp - 4], eax
            //   75dd                 | jne                 0xffffffdf
            //   2945f8               | sub                 dword ptr [ebp - 8], eax
            //   75d1                 | jne                 0xffffffd3
            //   5f                   | pop                 edi

        $sequence_5 = { c1e706 8b048580ee4500 8d44380c 50 ff15???????? }
            // n = 5, score = 200
            //   c1e706               | shl                 edi, 6
            //   8b048580ee4500       | mov                 eax, dword ptr [eax*4 + 0x45ee80]
            //   8d44380c             | lea                 eax, [eax + edi + 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { c1e804 03d6 8a1410 885101 }
            // n = 4, score = 200
            //   c1e804               | shr                 eax, 4
            //   03d6                 | add                 edx, esi
            //   8a1410               | mov                 dl, byte ptr [eax + edx]
            //   885101               | mov                 byte ptr [ecx + 1], dl

        $sequence_7 = { 85c0 0f85b9010000 8b8530efffff 40 898530efffff 83f80a }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   0f85b9010000         | jne                 0x1bf
            //   8b8530efffff         | mov                 eax, dword ptr [ebp - 0x10d0]
            //   40                   | inc                 eax
            //   898530efffff         | mov                 dword ptr [ebp - 0x10d0], eax
            //   83f80a               | cmp                 eax, 0xa

        $sequence_8 = { 8d85f8feffff 50 68???????? ffd6 85c0 }
            // n = 5, score = 200
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8b550c 895004 894808 8b4df4 89580c }
            // n = 5, score = 200
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   895004               | mov                 dword ptr [eax + 4], edx
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   89580c               | mov                 dword ptr [eax + 0xc], ebx

    condition:
        7 of them and filesize < 808960
}