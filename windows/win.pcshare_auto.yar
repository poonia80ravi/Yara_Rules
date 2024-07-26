rule win_pcshare_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pcshare."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pcshare"
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
        $sequence_0 = { 8d6b10 8974241c 85ff 897c2410 7457 }
            // n = 5, score = 100
            //   8d6b10               | lea                 ebp, [ebx + 0x10]
            //   8974241c             | mov                 dword ptr [esp + 0x1c], esi
            //   85ff                 | test                edi, edi
            //   897c2410             | mov                 dword ptr [esp + 0x10], edi
            //   7457                 | je                  0x59

        $sequence_1 = { 83ec14 8b542428 53 33db 56 8b0a 8b4204 }
            // n = 7, score = 100
            //   83ec14               | sub                 esp, 0x14
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]

        $sequence_2 = { 51 e8???????? 8bf0 83c9ff 8bfe 33c0 83c404 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c9ff               | or                  ecx, 0xffffffff
            //   8bfe                 | mov                 edi, esi
            //   33c0                 | xor                 eax, eax
            //   83c404               | add                 esp, 4

        $sequence_3 = { 6685db 744a 0fb6c3 f680e184061004 741a 8a4601 }
            // n = 6, score = 100
            //   6685db               | test                bx, bx
            //   744a                 | je                  0x4c
            //   0fb6c3               | movzx               eax, bl
            //   f680e184061004       | test                byte ptr [eax + 0x100684e1], 4
            //   741a                 | je                  0x1c
            //   8a4601               | mov                 al, byte ptr [esi + 1]

        $sequence_4 = { 81e7ffff0000 8b0481 c1e705 8b4c380c 8d44380c 81c900002000 8908 }
            // n = 7, score = 100
            //   81e7ffff0000         | and                 edi, 0xffff
            //   8b0481               | mov                 eax, dword ptr [ecx + eax*4]
            //   c1e705               | shl                 edi, 5
            //   8b4c380c             | mov                 ecx, dword ptr [eax + edi + 0xc]
            //   8d44380c             | lea                 eax, [eax + edi + 0xc]
            //   81c900002000         | or                  ecx, 0x200000
            //   8908                 | mov                 dword ptr [eax], ecx

        $sequence_5 = { 7ccc a1???????? 8b542428 2bc2 83f801 }
            // n = 5, score = 100
            //   7ccc                 | jl                  0xffffffce
            //   a1????????           |                     
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   2bc2                 | sub                 eax, edx
            //   83f801               | cmp                 eax, 1

        $sequence_6 = { 83c408 85c0 740d 8b16 42 }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   42                   | inc                 edx

        $sequence_7 = { 8b30 8b48fc 03f7 8b78f8 8bd1 03fb }
            // n = 6, score = 100
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   8b48fc               | mov                 ecx, dword ptr [eax - 4]
            //   03f7                 | add                 esi, edi
            //   8b78f8               | mov                 edi, dword ptr [eax - 8]
            //   8bd1                 | mov                 edx, ecx
            //   03fb                 | add                 edi, ebx

        $sequence_8 = { 8bce e8???????? 8b4c2418 5d 3bcb 742e 8a41ff }
            // n = 7, score = 100
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   5d                   | pop                 ebp
            //   3bcb                 | cmp                 ecx, ebx
            //   742e                 | je                  0x30
            //   8a41ff               | mov                 al, byte ptr [ecx - 1]

        $sequence_9 = { 8bd9 81e1ffff0000 c1e002 89442418 57 8b0406 }
            // n = 6, score = 100
            //   8bd9                 | mov                 ebx, ecx
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   c1e002               | shl                 eax, 2
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   57                   | push                edi
            //   8b0406               | mov                 eax, dword ptr [esi + eax]

    condition:
        7 of them and filesize < 893708
}