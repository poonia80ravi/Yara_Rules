rule win_tokyox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.tokyox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tokyox"
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
        $sequence_0 = { ff75e0 6a01 e8???????? 8bcb 8d5102 0f1f8000000000 668b01 }
            // n = 7, score = 200
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   8d5102               | lea                 edx, [ecx + 2]
            //   0f1f8000000000       | nop                 dword ptr [eax]
            //   668b01               | mov                 ax, word ptr [ecx]

        $sequence_1 = { 51 ffd7 c7460800000000 8b4604 85c0 740a 50 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   c7460800000000       | mov                 dword ptr [esi + 8], 0
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   50                   | push                eax

        $sequence_2 = { 0f57c0 8945d0 83c404 660f1345f4 c745fc00000000 }
            // n = 5, score = 200
            //   0f57c0               | xorps               xmm0, xmm0
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   83c404               | add                 esp, 4
            //   660f1345f4           | movlpd              qword ptr [ebp - 0xc], xmm0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_3 = { 57 3bc6 0f823e010000 8b7b14 8d0432 8bf0 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   3bc6                 | cmp                 eax, esi
            //   0f823e010000         | jb                  0x144
            //   8b7b14               | mov                 edi, dword ptr [ebx + 0x14]
            //   8d0432               | lea                 eax, [edx + esi]
            //   8bf0                 | mov                 esi, eax

        $sequence_4 = { ff15???????? 8945e4 33db 40 b902000000 f7e1 0f90c3 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   33db                 | xor                 ebx, ebx
            //   40                   | inc                 eax
            //   b902000000           | mov                 ecx, 2
            //   f7e1                 | mul                 ecx
            //   0f90c3               | seto                bl

        $sequence_5 = { 8b4508 81ecb4000000 53 56 }
            // n = 4, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   81ecb4000000         | sub                 esp, 0xb4
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_6 = { 68e9fd0000 ff15???????? 894508 33db 40 b902000000 }
            // n = 6, score = 200
            //   68e9fd0000           | push                0xfde9
            //   ff15????????         |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   33db                 | xor                 ebx, ebx
            //   40                   | inc                 eax
            //   b902000000           | mov                 ecx, 2

        $sequence_7 = { 56 0f1145d0 895db8 0f114590 0f104010 0f1145c0 0f1145a0 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   0f1145d0             | movups              xmmword ptr [ebp - 0x30], xmm0
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx
            //   0f114590             | movups              xmmword ptr [ebp - 0x70], xmm0
            //   0f104010             | movups              xmm0, xmmword ptr [eax + 0x10]
            //   0f1145c0             | movups              xmmword ptr [ebp - 0x40], xmm0
            //   0f1145a0             | movups              xmmword ptr [ebp - 0x60], xmm0

        $sequence_8 = { 8b75fc 8b45f8 3bfb 7410 4f eb9d 2bfb }
            // n = 7, score = 200
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   3bfb                 | cmp                 edi, ebx
            //   7410                 | je                  0x12
            //   4f                   | dec                 edi
            //   eb9d                 | jmp                 0xffffff9f
            //   2bfb                 | sub                 edi, ebx

        $sequence_9 = { 668903 8d5101 8a01 41 84c0 75f9 ff75f8 }
            // n = 7, score = 200
            //   668903               | mov                 word ptr [ebx], ax
            //   8d5101               | lea                 edx, [ecx + 1]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   ff75f8               | push                dword ptr [ebp - 8]

    condition:
        7 of them and filesize < 237568
}