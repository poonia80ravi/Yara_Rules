rule win_crat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.crat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crat"
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
        $sequence_0 = { 7406 e8???????? 90 488b542420 }
            // n = 4, score = 500
            //   7406                 | je                  8
            //   e8????????           |                     
            //   90                   | nop                 
            //   488b542420           | dec                 eax

        $sequence_1 = { e8???????? 488bd0 488d8d00010000 e8???????? 90 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   488bd0               | dec                 eax
            //   488d8d00010000       | lea                 ecx, [ebp + 0xe8]
            //   e8????????           |                     
            //   90                   | nop                 

        $sequence_2 = { e8???????? 488bd0 488d8d88010000 e8???????? 90 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   488bd0               | dec                 eax
            //   488d8d88010000       | mov                 edx, eax
            //   e8????????           |                     
            //   90                   | dec                 eax

        $sequence_3 = { e8???????? 488bd0 488d8d70010000 e8???????? }
            // n = 4, score = 500
            //   e8????????           |                     
            //   488bd0               | dec                 eax
            //   488d8d70010000       | mov                 edx, eax
            //   e8????????           |                     

        $sequence_4 = { e8???????? 488bd0 488d8d20010000 e8???????? 90 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   488bd0               | lea                 ecx, [ebp + 0x170]
            //   488d8d20010000       | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 edx, eax

        $sequence_5 = { e8???????? 488bd0 488d8de8000000 e8???????? 90 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   488bd0               | mov                 edx, dword ptr [esp + 0x20]
            //   488d8de8000000       | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 edx, eax

        $sequence_6 = { 488bd0 488d8d28030000 e8???????? 90 }
            // n = 4, score = 500
            //   488bd0               | dec                 eax
            //   488d8d28030000       | lea                 ecx, [ebp + 0x100]
            //   e8????????           |                     
            //   90                   | nop                 

        $sequence_7 = { e8???????? 488bd0 488d4d90 e8???????? 90 488bd0 }
            // n = 6, score = 500
            //   e8????????           |                     
            //   488bd0               | dec                 eax
            //   488d4d90             | lea                 ecx, [ebp + 0x328]
            //   e8????????           |                     
            //   90                   | nop                 
            //   488bd0               | dec                 eax

        $sequence_8 = { 33d2 c1e902 f7f1 eb02 }
            // n = 4, score = 300
            //   33d2                 | push                esi
            //   c1e902               | cmp                 dword ptr [edi + 0x18], 0
            //   f7f1                 | mov                 ecx, dword ptr [ecx + 0x48]
            //   eb02                 | sub                 ecx, 0x10

        $sequence_9 = { ffd0 85c0 750f ff15???????? 83f87a }
            // n = 5, score = 300
            //   ffd0                 | dec                 eax
            //   85c0                 | lea                 ecx, [ebp + 0x120]
            //   750f                 | nop                 
            //   ff15????????         |                     
            //   83f87a               | dec                 eax

        $sequence_10 = { ff75d0 e8???????? 83c404 ff75cc e8???????? 83c404 8bc6 }
            // n = 7, score = 200
            //   ff75d0               | push                esi
            //   e8????????           |                     
            //   83c404               | cmp                 dword ptr [edi + 0x18], 0
            //   ff75cc               | jne                 0x116
            //   e8????????           |                     
            //   83c404               | push                dword ptr [ebp - 4]
            //   8bc6                 | mov                 ecx, edi

        $sequence_11 = { ff7610 e8???????? 56 e8???????? 83c408 ff7720 }
            // n = 6, score = 200
            //   ff7610               | cmp                 byte ptr [ebp - 0x1f], 0
            //   e8????????           |                     
            //   56                   | je                  0x14
            //   e8????????           |                     
            //   83c408               | push                dword ptr [ebp - 0x28]
            //   ff7720               | jmp                 0x30

        $sequence_12 = { ff7720 e8???????? ff771c e8???????? }
            // n = 4, score = 200
            //   ff7720               | je                  0x19
            //   e8????????           |                     
            //   ff771c               | mov                 eax, dword ptr [ebp - 0x38]
            //   e8????????           |                     

        $sequence_13 = { ff75fc 8bcf 33db 56 }
            // n = 4, score = 200
            //   ff75fc               | push                dword ptr [ebp - 0x28]
            //   8bcf                 | jmp                 0x33
            //   33db                 | cmp                 byte ptr [ebp - 0x1f], 0
            //   56                   | je                  0x19

        $sequence_14 = { ff75d8 e8???????? eb2e 807de100 }
            // n = 4, score = 200
            //   ff75d8               | mov                 eax, esi
            //   e8????????           |                     
            //   eb2e                 | mov                 ecx, dword ptr [ebp - 0xc]
            //   807de100             | mov                 dword ptr fs:[0], ecx

        $sequence_15 = { ff75fc 8bcf 56 e8???????? 837f1800 0f847affffff }
            // n = 6, score = 200
            //   ff75fc               | nop                 
            //   8bcf                 | dec                 eax
            //   56                   | mov                 edx, eax
            //   e8????????           |                     
            //   837f1800             | dec                 eax
            //   0f847affffff         | mov                 edx, eax

        $sequence_16 = { ff75a4 c745a800000000 e8???????? 83c408 c745a400000000 eb0e }
            // n = 6, score = 200
            //   ff75a4               | push                dword ptr [ebp - 0x30]
            //   c745a800000000       | add                 esp, 4
            //   e8????????           |                     
            //   83c408               | push                dword ptr [ebp - 0x34]
            //   c745a400000000       | add                 esp, 4
            //   eb0e                 | mov                 eax, esi

    condition:
        7 of them and filesize < 4161536
}