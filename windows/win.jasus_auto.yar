rule win_jasus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.jasus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jasus"
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
        $sequence_0 = { 0fb715???????? a1???????? 56 8d7116 8945f0 8b06 }
            // n = 6, score = 200
            //   0fb715????????       |                     
            //   a1????????           |                     
            //   56                   | push                esi
            //   8d7116               | lea                 esi, [ecx + 0x16]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_1 = { 7404 3c20 7503 41 ebf3 8bf9 68???????? }
            // n = 7, score = 200
            //   7404                 | je                  6
            //   3c20                 | cmp                 al, 0x20
            //   7503                 | jne                 5
            //   41                   | inc                 ecx
            //   ebf3                 | jmp                 0xfffffff5
            //   8bf9                 | mov                 edi, ecx
            //   68????????           |                     

        $sequence_2 = { 324dfe 80e17f 3008 8b06 8bc8 c1f905 8b0c8d809d4300 }
            // n = 7, score = 200
            //   324dfe               | xor                 cl, byte ptr [ebp - 2]
            //   80e17f               | and                 cl, 0x7f
            //   3008                 | xor                 byte ptr [eax], cl
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d809d4300       | mov                 ecx, dword ptr [ecx*4 + 0x439d80]

        $sequence_3 = { 8a55fe 8aca c0e902 8adf c0e206 0255ff }
            // n = 6, score = 200
            //   8a55fe               | mov                 dl, byte ptr [ebp - 2]
            //   8aca                 | mov                 cl, dl
            //   c0e902               | shr                 cl, 2
            //   8adf                 | mov                 bl, bh
            //   c0e206               | shl                 dl, 6
            //   0255ff               | add                 dl, byte ptr [ebp - 1]

        $sequence_4 = { 83c408 8b4514 85c0 740f 50 68???????? 56 }
            // n = 7, score = 200
            //   83c408               | add                 esp, 8
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_5 = { c70009000000 e8???????? ebde 8bc8 83e01f c1f905 8b0c8d809d4300 }
            // n = 7, score = 200
            //   c70009000000         | mov                 dword ptr [eax], 9
            //   e8????????           |                     
            //   ebde                 | jmp                 0xffffffe0
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d809d4300       | mov                 ecx, dword ptr [ecx*4 + 0x439d80]

        $sequence_6 = { 68???????? 50 43 e8???????? 8bf0 }
            // n = 5, score = 200
            //   68????????           |                     
            //   50                   | push                eax
            //   43                   | inc                 ebx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_7 = { 83c408 85db 7514 68???????? 56 }
            // n = 5, score = 200
            //   83c408               | add                 esp, 8
            //   85db                 | test                ebx, ebx
            //   7514                 | jne                 0x16
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_8 = { 5d c3 8b4720 85c0 7410 50 e8???????? }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b4720               | mov                 eax, dword ptr [edi + 0x20]
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { 41 000438 41 0023 d18a0688078a 46 018847018a46 }
            // n = 7, score = 200
            //   41                   | inc                 ecx
            //   000438               | add                 byte ptr [eax + edi], al
            //   41                   | inc                 ecx
            //   0023                 | add                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi
            //   018847018a46         | add                 dword ptr [eax + 0x468a0147], ecx

    condition:
        7 of them and filesize < 507904
}