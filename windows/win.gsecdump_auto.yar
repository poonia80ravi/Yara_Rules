rule win_gsecdump_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gsecdump."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gsecdump"
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
        $sequence_0 = { 7503 32c0 c3 8b4c2404 668901 b001 c3 }
            // n = 7, score = 100
            //   7503                 | jne                 5
            //   32c0                 | xor                 al, al
            //   c3                   | ret                 
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   668901               | mov                 word ptr [ecx], ax
            //   b001                 | mov                 al, 1
            //   c3                   | ret                 

        $sequence_1 = { c78424840000004cee4300 8d942484000000 52 c68424b800000002 e8???????? }
            // n = 5, score = 100
            //   c78424840000004cee4300     | mov    dword ptr [esp + 0x84], 0x43ee4c
            //   8d942484000000       | lea                 edx, [esp + 0x84]
            //   52                   | push                edx
            //   c68424b800000002     | mov                 byte ptr [esp + 0xb8], 2
            //   e8????????           |                     

        $sequence_2 = { 68???????? 8d4db4 51 e8???????? 8d55d8 52 68???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_3 = { e9???????? 56 e8???????? 83c404 b801000000 8b4c2428 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   b801000000           | mov                 eax, 1
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]

        $sequence_4 = { 7437 8b74242c 83642418fe 3bf3 742a 8d4e04 }
            // n = 6, score = 100
            //   7437                 | je                  0x39
            //   8b74242c             | mov                 esi, dword ptr [esp + 0x2c]
            //   83642418fe           | and                 dword ptr [esp + 0x18], 0xfffffffe
            //   3bf3                 | cmp                 esi, ebx
            //   742a                 | je                  0x2c
            //   8d4e04               | lea                 ecx, [esi + 4]

        $sequence_5 = { 7505 e8???????? 837f1810 7205 8b4704 eb03 8d4704 }
            // n = 7, score = 100
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   837f1810             | cmp                 dword ptr [edi + 0x18], 0x10
            //   7205                 | jb                  7
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   eb03                 | jmp                 5
            //   8d4704               | lea                 eax, [edi + 4]

        $sequence_6 = { 663dffff 7412 ff764c e8???????? 85c0 59 7d05 }
            // n = 7, score = 100
            //   663dffff             | cmp                 ax, 0xffff
            //   7412                 | je                  0x14
            //   ff764c               | push                dword ptr [esi + 0x4c]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   7d05                 | jge                 7

        $sequence_7 = { 6a0a b9???????? e8???????? 8b15???????? 8b4204 33f6 f680288e440006 }
            // n = 7, score = 100
            //   6a0a                 | push                0xa
            //   b9????????           |                     
            //   e8????????           |                     
            //   8b15????????         |                     
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   33f6                 | xor                 esi, esi
            //   f680288e440006       | test                byte ptr [eax + 0x448e28], 6

        $sequence_8 = { 8d4c2424 c68424ec00000005 8974243c 895c2438 66895c2428 e8???????? 8d442450 }
            // n = 7, score = 100
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   c68424ec00000005     | mov                 byte ptr [esp + 0xec], 5
            //   8974243c             | mov                 dword ptr [esp + 0x3c], esi
            //   895c2438             | mov                 dword ptr [esp + 0x38], ebx
            //   66895c2428           | mov                 word ptr [esp + 0x28], bx
            //   e8????????           |                     
            //   8d442450             | lea                 eax, [esp + 0x50]

        $sequence_9 = { 57 8d931c080000 52 56 8b45d0 50 ff15???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8d931c080000         | lea                 edx, [ebx + 0x81c]
            //   52                   | push                edx
            //   56                   | push                esi
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   50                   | push                eax
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 630784
}