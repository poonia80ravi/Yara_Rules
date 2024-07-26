rule win_whispergate_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.whispergate."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.whispergate"
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
        $sequence_0 = { 8b55b4 0fb6440c0b 3c2f 7426 3c5c 7422 89c8 }
            // n = 7, score = 300
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]
            //   0fb6440c0b           | movzx               eax, byte ptr [esp + ecx + 0xb]
            //   3c2f                 | cmp                 al, 0x2f
            //   7426                 | je                  0x28
            //   3c5c                 | cmp                 al, 0x5c
            //   7422                 | je                  0x24
            //   89c8                 | mov                 eax, ecx

        $sequence_1 = { 0fa2 31c0 f6c601 7403 83c801 f6c520 }
            // n = 6, score = 300
            //   0fa2                 | cpuid               
            //   31c0                 | xor                 eax, eax
            //   f6c601               | test                dh, 1
            //   7403                 | je                  5
            //   83c801               | or                  eax, 1
            //   f6c520               | test                ch, 0x20

        $sequence_2 = { 3b5c241c 744f 0fbe5f01 83c701 }
            // n = 4, score = 300
            //   3b5c241c             | cmp                 ebx, dword ptr [esp + 0x1c]
            //   744f                 | je                  0x51
            //   0fbe5f01             | movsx               ebx, byte ptr [edi + 1]
            //   83c701               | add                 edi, 1

        $sequence_3 = { 83c001 84d2 8856ff 75e4 890c24 e8???????? }
            // n = 6, score = 300
            //   83c001               | add                 eax, 1
            //   84d2                 | test                dl, dl
            //   8856ff               | mov                 byte ptr [esi - 1], dl
            //   75e4                 | jne                 0xffffffe6
            //   890c24               | mov                 dword ptr [esp], ecx
            //   e8????????           |                     

        $sequence_4 = { 813e???????? 740e 83c410 5b 5e }
            // n = 5, score = 300
            //   813e????????         |                     
            //   740e                 | je                  0x10
            //   83c410               | add                 esp, 0x10
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_5 = { 0fb640ff 8955c8 8845a3 0fb645a3 }
            // n = 4, score = 300
            //   0fb640ff             | movzx               eax, byte ptr [eax - 1]
            //   8955c8               | mov                 dword ptr [ebp - 0x38], edx
            //   8845a3               | mov                 byte ptr [ebp - 0x5d], al
            //   0fb645a3             | movzx               eax, byte ptr [ebp - 0x5d]

        $sequence_6 = { 83c308 039100004000 8d8100004000 b904000000 8954241c }
            // n = 5, score = 300
            //   83c308               | add                 ebx, 8
            //   039100004000         | add                 edx, dword ptr [ecx + 0x400000]
            //   8d8100004000         | lea                 eax, [ecx + 0x400000]
            //   b904000000           | mov                 ecx, 4
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx

        $sequence_7 = { 75f0 8b4508 890424 8b75d0 8b4dc4 8b45c8 }
            // n = 6, score = 300
            //   75f0                 | jne                 0xfffffff2
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax
            //   8b75d0               | mov                 esi, dword ptr [ebp - 0x30]
            //   8b4dc4               | mov                 ecx, dword ptr [ebp - 0x3c]
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]

        $sequence_8 = { c7861401000000000000 c70600000000 66894604 81c42c010000 89f0 }
            // n = 5, score = 300
            //   c7861401000000000000     | mov    dword ptr [esi + 0x114], 0
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   66894604             | mov                 word ptr [esi + 4], ax
            //   81c42c010000         | add                 esp, 0x12c
            //   89f0                 | mov                 eax, esi

        $sequence_9 = { 8b45bc 8b4004 83c304 890424 }
            // n = 4, score = 300
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   83c304               | add                 ebx, 4
            //   890424               | mov                 dword ptr [esp], eax

    condition:
        7 of them and filesize < 114688
}