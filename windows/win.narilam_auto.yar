rule win_narilam_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.narilam."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.narilam"
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
        $sequence_0 = { db3c24 9b 668b13 8bc6 66b90600 e8???????? e9???????? }
            // n = 7, score = 100
            //   db3c24               | fstp                xword ptr [esp]
            //   9b                   | wait                
            //   668b13               | mov                 dx, word ptr [ebx]
            //   8bc6                 | mov                 eax, esi
            //   66b90600             | mov                 cx, 6
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_1 = { ff75b0 ff75ac ff75a8 ff75a4 8d45a0 e8???????? 50 }
            // n = 7, score = 100
            //   ff75b0               | push                dword ptr [ebp - 0x50]
            //   ff75ac               | push                dword ptr [ebp - 0x54]
            //   ff75a8               | push                dword ptr [ebp - 0x58]
            //   ff75a4               | push                dword ptr [ebp - 0x5c]
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_2 = { e9???????? dd4308 db7c2408 9b e9???????? df6b08 d835???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   dd4308               | fld                 qword ptr [ebx + 8]
            //   db7c2408             | fstp                xword ptr [esp + 8]
            //   9b                   | wait                
            //   e9????????           |                     
            //   df6b08               | fild                qword ptr [ebx + 8]
            //   d835????????         |                     

        $sequence_3 = { e8???????? 8b7008 85f6 7518 8bd3 8b45fc e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b7008               | mov                 esi, dword ptr [eax + 8]
            //   85f6                 | test                esi, esi
            //   7518                 | jne                 0x1a
            //   8bd3                 | mov                 edx, ebx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_4 = { e8???????? 0fb66c240d 0fb67c240e f6430180 0f95c0 8bd8 8b0424 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0fb66c240d           | movzx               ebp, byte ptr [esp + 0xd]
            //   0fb67c240e           | movzx               edi, byte ptr [esp + 0xe]
            //   f6430180             | test                byte ptr [ebx + 1], 0x80
            //   0f95c0               | setne               al
            //   8bd8                 | mov                 ebx, eax
            //   8b0424               | mov                 eax, dword ptr [esp]

        $sequence_5 = { eb17 8bc6 8b15???????? e8???????? 84c0 7406 89be80000000 }
            // n = 7, score = 100
            //   eb17                 | jmp                 0x19
            //   8bc6                 | mov                 eax, esi
            //   8b15????????         |                     
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7406                 | je                  8
            //   89be80000000         | mov                 dword ptr [esi + 0x80], edi

        $sequence_6 = { 8bcb 49 ba01000000 8bc6 e8???????? 8b55f8 8b45fc }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   49                   | dec                 ecx
            //   ba01000000           | mov                 edx, 1
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { ba03000000 8b45a8 8b08 ff51fc 66c7458c9800 8b8574ffffff 8945a0 }
            // n = 7, score = 100
            //   ba03000000           | mov                 edx, 3
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff51fc               | call                dword ptr [ecx - 4]
            //   66c7458c9800         | mov                 word ptr [ebp - 0x74], 0x98
            //   8b8574ffffff         | mov                 eax, dword ptr [ebp - 0x8c]
            //   8945a0               | mov                 dword ptr [ebp - 0x60], eax

        $sequence_8 = { 0f8467ffffff 33c0 5a 59 59 648910 68???????? }
            // n = 7, score = 100
            //   0f8467ffffff         | je                  0xffffff6d
            //   33c0                 | xor                 eax, eax
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   648910               | mov                 dword ptr fs:[eax], edx
            //   68????????           |                     

        $sequence_9 = { 8bd8 8bc3 e8???????? 837b3400 7418 8b5338 8bc6 }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   837b3400             | cmp                 dword ptr [ebx + 0x34], 0
            //   7418                 | je                  0x1a
            //   8b5338               | mov                 edx, dword ptr [ebx + 0x38]
            //   8bc6                 | mov                 eax, esi

    condition:
        7 of them and filesize < 3325952
}