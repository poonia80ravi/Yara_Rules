rule win_unidentified_081_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_081."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_081"
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
        $sequence_0 = { c3 55 8bec 56 8b7508 833cf530bd410000 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   833cf530bd410000     | cmp                 dword ptr [esi*8 + 0x41bd30], 0

        $sequence_1 = { 8b1495d0d14100 898d24e5ffff 8a5c1124 02db d0fb }
            // n = 5, score = 100
            //   8b1495d0d14100       | mov                 edx, dword ptr [edx*4 + 0x41d1d0]
            //   898d24e5ffff         | mov                 dword ptr [ebp - 0x1adc], ecx
            //   8a5c1124             | mov                 bl, byte ptr [ecx + edx + 0x24]
            //   02db                 | add                 bl, bl
            //   d0fb                 | sar                 bl, 1

        $sequence_2 = { e8???????? 83c404 68???????? ff15???????? 8b5c2414 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]

        $sequence_3 = { 83c408 85c0 0f85e7000000 8d85d0fdffff 50 }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   0f85e7000000         | jne                 0xed
            //   8d85d0fdffff         | lea                 eax, [ebp - 0x230]
            //   50                   | push                eax

        $sequence_4 = { 80ea57 eb02 32d2 8bc6 c0e104 d1e8 02ca }
            // n = 7, score = 100
            //   80ea57               | sub                 dl, 0x57
            //   eb02                 | jmp                 4
            //   32d2                 | xor                 dl, dl
            //   8bc6                 | mov                 eax, esi
            //   c0e104               | shl                 cl, 4
            //   d1e8                 | shr                 eax, 1
            //   02ca                 | add                 cl, dl

        $sequence_5 = { 85c0 0f8403010000 8d85d0fdffff 68???????? 50 e8???????? 83c408 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f8403010000         | je                  0x109
            //   8d85d0fdffff         | lea                 eax, [ebp - 0x230]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_6 = { 8b0485d0d14100 f644030401 7428 57 e8???????? 59 50 }
            // n = 7, score = 100
            //   8b0485d0d14100       | mov                 eax, dword ptr [eax*4 + 0x41d1d0]
            //   f644030401           | test                byte ptr [ebx + eax + 4], 1
            //   7428                 | je                  0x2a
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax

        $sequence_7 = { ff15???????? 8b8534ffffff 85c0 0f8480000000 6a01 6a00 f7d8 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b8534ffffff         | mov                 eax, dword ptr [ebp - 0xcc]
            //   85c0                 | test                eax, eax
            //   0f8480000000         | je                  0x86
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   f7d8                 | neg                 eax

        $sequence_8 = { e8???????? 83c404 a3???????? 8d442418 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax

        $sequence_9 = { 8a08 8a5001 8a6802 8a70ff }
            // n = 4, score = 100
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   8a5001               | mov                 dl, byte ptr [eax + 1]
            //   8a6802               | mov                 ch, byte ptr [eax + 2]
            //   8a70ff               | mov                 dh, byte ptr [eax - 1]

    condition:
        7 of them and filesize < 273408
}