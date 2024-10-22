rule win_turnedup_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.turnedup."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.turnedup"
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
        $sequence_0 = { ffd0 8b4d08 8b16 51 52 e8???????? 884604 }
            // n = 7, score = 400
            //   ffd0                 | call                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   884604               | mov                 byte ptr [esi + 4], al

        $sequence_1 = { 51 c746140f000000 c7461000000000 57 8bce c60600 e8???????? }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   c60600               | mov                 byte ptr [esi], 0
            //   e8????????           |                     

        $sequence_2 = { 7303 8d4d28 57 56 50 51 68???????? }
            // n = 7, score = 400
            //   7303                 | jae                 5
            //   8d4d28               | lea                 ecx, [ebp + 0x28]
            //   57                   | push                edi
            //   56                   | push                esi
            //   50                   | push                eax
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_3 = { 8d8c24e0000000 51 33c0 c644241c7c e8???????? }
            // n = 5, score = 400
            //   8d8c24e0000000       | lea                 ecx, [esp + 0xe0]
            //   51                   | push                ecx
            //   33c0                 | xor                 eax, eax
            //   c644241c7c           | mov                 byte ptr [esp + 0x1c], 0x7c
            //   e8????????           |                     

        $sequence_4 = { 750a 8b45bc c60030 40 8945bc 8b7db4 8bf3 }
            // n = 7, score = 400
            //   750a                 | jne                 0xc
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   c60030               | mov                 byte ptr [eax], 0x30
            //   40                   | inc                 eax
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   8b7db4               | mov                 edi, dword ptr [ebp - 0x4c]
            //   8bf3                 | mov                 esi, ebx

        $sequence_5 = { 8d550c 52 8d442434 50 ba00080000 8d4d14 e8???????? }
            // n = 7, score = 400
            //   8d550c               | lea                 edx, [ebp + 0xc]
            //   52                   | push                edx
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   50                   | push                eax
            //   ba00080000           | mov                 edx, 0x800
            //   8d4d14               | lea                 ecx, [ebp + 0x14]
            //   e8????????           |                     

        $sequence_6 = { eb02 8bc6 8b5e10 03d8 3bd9 7631 83fa10 }
            // n = 7, score = 400
            //   eb02                 | jmp                 4
            //   8bc6                 | mov                 eax, esi
            //   8b5e10               | mov                 ebx, dword ptr [esi + 0x10]
            //   03d8                 | add                 ebx, eax
            //   3bd9                 | cmp                 ebx, ecx
            //   7631                 | jbe                 0x33
            //   83fa10               | cmp                 edx, 0x10

        $sequence_7 = { 85db 750f 8b45e0 83ff10 7303 8d45e0 3a08 }
            // n = 7, score = 400
            //   85db                 | test                ebx, ebx
            //   750f                 | jne                 0x11
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   83ff10               | cmp                 edi, 0x10
            //   7303                 | jae                 5
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   3a08                 | cmp                 cl, byte ptr [eax]

        $sequence_8 = { 40 3bc6 72f3 33c0 85f6 7415 }
            // n = 6, score = 400
            //   40                   | inc                 eax
            //   3bc6                 | cmp                 eax, esi
            //   72f3                 | jb                  0xfffffff5
            //   33c0                 | xor                 eax, eax
            //   85f6                 | test                esi, esi
            //   7415                 | je                  0x17

        $sequence_9 = { 7612 8d642400 8a1408 c0ca02 881408 40 }
            // n = 6, score = 400
            //   7612                 | jbe                 0x14
            //   8d642400             | lea                 esp, [esp]
            //   8a1408               | mov                 dl, byte ptr [eax + ecx]
            //   c0ca02               | ror                 dl, 2
            //   881408               | mov                 byte ptr [eax + ecx], dl
            //   40                   | inc                 eax

    condition:
        7 of them and filesize < 892928
}