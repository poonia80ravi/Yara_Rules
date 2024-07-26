rule win_mapiget_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mapiget."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mapiget"
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
        $sequence_0 = { 5b c3 83fb01 7e61 8b442418 8d7804 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   83fb01               | cmp                 ebx, 1
            //   7e61                 | jle                 0x63
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8d7804               | lea                 edi, [eax + 4]

        $sequence_1 = { e8???????? 83c408 85c0 7520 8d8df0f9ffff }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7520                 | jne                 0x22
            //   8d8df0f9ffff         | lea                 ecx, [ebp - 0x610]

        $sequence_2 = { d1f8 48 c3 55 8bec 837d0c00 56 }
            // n = 7, score = 100
            //   d1f8                 | sar                 eax, 1
            //   48                   | dec                 eax
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   56                   | push                esi

        $sequence_3 = { 83c42c 5f eb26 8d4508 8db674eb4000 6a00 50 }
            // n = 7, score = 100
            //   83c42c               | add                 esp, 0x2c
            //   5f                   | pop                 edi
            //   eb26                 | jmp                 0x28
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8db674eb4000         | lea                 esi, [esi + 0x40eb74]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_4 = { 50 6a00 6800110000 ff15???????? 8b4c240c 51 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6800110000           | push                0x1100
            //   ff15????????         |                     
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   51                   | push                ecx

        $sequence_5 = { 8d9570ffffff 52 e8???????? 83c404 6683bc456effffff0a }
            // n = 5, score = 100
            //   8d9570ffffff         | lea                 edx, [ebp - 0x90]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6683bc456effffff0a     | cmp    word ptr [ebp + eax*2 - 0x92], 0xa

        $sequence_6 = { 33d2 8a9178154000 ff24956c154000 6683780400 74c0 6683780800 }
            // n = 6, score = 100
            //   33d2                 | xor                 edx, edx
            //   8a9178154000         | mov                 dl, byte ptr [ecx + 0x401578]
            //   ff24956c154000       | jmp                 dword ptr [edx*4 + 0x40156c]
            //   6683780400           | cmp                 word ptr [eax + 4], 0
            //   74c0                 | je                  0xffffffc2
            //   6683780800           | cmp                 word ptr [eax + 8], 0

        $sequence_7 = { 8d34b5e0ea4000 832600 83c60c 4a 75f7 8b00 }
            // n = 6, score = 100
            //   8d34b5e0ea4000       | lea                 esi, [esi*4 + 0x40eae0]
            //   832600               | and                 dword ptr [esi], 0
            //   83c60c               | add                 esi, 0xc
            //   4a                   | dec                 edx
            //   75f7                 | jne                 0xfffffff9
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_8 = { 50 e8???????? 83c404 6683bc45eefdffff0a 7517 8d8df0fdffff 51 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6683bc45eefdffff0a     | cmp    word ptr [ebp + eax*2 - 0x212], 0xa
            //   7517                 | jne                 0x19
            //   8d8df0fdffff         | lea                 ecx, [ebp - 0x210]
            //   51                   | push                ecx

        $sequence_9 = { 7f04 33c0 eb33 ff4d0c 7428 ff7510 e8???????? }
            // n = 7, score = 100
            //   7f04                 | jg                  6
            //   33c0                 | xor                 eax, eax
            //   eb33                 | jmp                 0x35
            //   ff4d0c               | dec                 dword ptr [ebp + 0xc]
            //   7428                 | je                  0x2a
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 163840
}