rule win_quantloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.quantloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quantloader"
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
        $sequence_0 = { 40 8945f0 eb13 ff4508 eba1 8b45f4 }
            // n = 6, score = 500
            //   40                   | inc                 eax
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   eb13                 | jmp                 0x15
            //   ff4508               | inc                 dword ptr [ebp + 8]
            //   eba1                 | jmp                 0xffffffa3
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_1 = { 83ec18 89049d10804000 eb44 8b1d???????? c744241400000000 c744241000000000 c744240c00000000 }
            // n = 7, score = 500
            //   83ec18               | sub                 esp, 0x18
            //   89049d10804000       | mov                 dword ptr [ebx*4 + 0x408010], eax
            //   eb44                 | jmp                 0x46
            //   8b1d????????         |                     
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   c744240c00000000     | mov                 dword ptr [esp + 0xc], 0

        $sequence_2 = { e8???????? c7442408???????? 89442404 c7042401000080 e8???????? 89442404 c70424???????? }
            // n = 7, score = 500
            //   e8????????           |                     
            //   c7442408????????     |                     
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c7042401000080       | mov                 dword ptr [esp], 0x80000001
            //   e8????????           |                     
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c70424????????       |                     

        $sequence_3 = { 0fb645ff 83f801 751e c70424???????? e8???????? }
            // n = 5, score = 500
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]
            //   83f801               | cmp                 eax, 1
            //   751e                 | jne                 0x20
            //   c70424????????       |                     
            //   e8????????           |                     

        $sequence_4 = { 89542404 c7042401000080 e8???????? c744240400000000 c70424???????? e8???????? }
            // n = 6, score = 500
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   c7042401000080       | mov                 dword ptr [esp], 0x80000001
            //   e8????????           |                     
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   c70424????????       |                     
            //   e8????????           |                     

        $sequence_5 = { e8???????? 83ec04 c745f400000000 eb00 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   83ec04               | sub                 esp, 4
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   eb00                 | jmp                 2

        $sequence_6 = { 83ec08 8945f8 837df800 7405 }
            // n = 4, score = 500
            //   83ec08               | sub                 esp, 8
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7405                 | je                  7

        $sequence_7 = { 891424 e8???????? 8b4510 89442404 }
            // n = 4, score = 500
            //   891424               | mov                 dword ptr [esp], edx
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89442404             | mov                 dword ptr [esp + 4], eax

        $sequence_8 = { 57 bf02000000 e8???????? 5f 5d c20c00 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   bf02000000           | mov                 edi, 2
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc

        $sequence_9 = { 64ff3530000000 59 8b490c 8b490c }
            // n = 4, score = 100
            //   64ff3530000000       | push                dword ptr fs:[0x30]
            //   59                   | pop                 ecx
            //   8b490c               | mov                 ecx, dword ptr [ecx + 0xc]
            //   8b490c               | mov                 ecx, dword ptr [ecx + 0xc]

        $sequence_10 = { ff5504 8bd8 8b7560 85f6 }
            // n = 4, score = 100
            //   ff5504               | call                dword ptr [ebp + 4]
            //   8bd8                 | mov                 ebx, eax
            //   8b7560               | mov                 esi, dword ptr [ebp + 0x60]
            //   85f6                 | test                esi, esi

        $sequence_11 = { 51 33c9 41 2bc2 }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   33c9                 | xor                 ecx, ecx
            //   41                   | inc                 ecx
            //   2bc2                 | sub                 eax, edx

        $sequence_12 = { 8bf8 58 57 ab }
            // n = 4, score = 100
            //   8bf8                 | mov                 edi, eax
            //   58                   | pop                 eax
            //   57                   | push                edi
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_13 = { 8b456c 85c0 7415 89463c 52 }
            // n = 5, score = 100
            //   8b456c               | mov                 eax, dword ptr [ebp + 0x6c]
            //   85c0                 | test                eax, eax
            //   7415                 | je                  0x17
            //   89463c               | mov                 dword ptr [esi + 0x3c], eax
            //   52                   | push                edx

        $sequence_14 = { 0f8481000000 03f3 ad 8bf8 03fb 50 }
            // n = 6, score = 100
            //   0f8481000000         | je                  0x87
            //   03f3                 | add                 esi, ebx
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   8bf8                 | mov                 edi, eax
            //   03fb                 | add                 edi, ebx
            //   50                   | push                eax

        $sequence_15 = { 037568 037d68 2b4d68 85c9 7413 ad 50 }
            // n = 7, score = 100
            //   037568               | add                 esi, dword ptr [ebp + 0x68]
            //   037d68               | add                 edi, dword ptr [ebp + 0x68]
            //   2b4d68               | sub                 ecx, dword ptr [ebp + 0x68]
            //   85c9                 | test                ecx, ecx
            //   7413                 | je                  0x15
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 155648
}