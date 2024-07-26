rule elf_bashlite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects elf.bashlite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite"
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
        $sequence_0 = { c785ecefffff00000000 8b85ecefffff c9 c3 }
            // n = 4, score = 300
            //   c785ecefffff00000000     | mov    eax, dword ptr [ebp - 0x18]
            //   8b85ecefffff         | movzx               edx, byte ptr [eax + 0xd]
            //   c9                   | or                  dl, 1
            //   c3                   | mov                 byte ptr [eax + 0xd], dl

        $sequence_1 = { c1f802 89c2 89d0 01c0 }
            // n = 4, score = 300
            //   c1f802               | mov                 eax, dword ptr [ebp + 0xc]
            //   89c2                 | add                 eax, 8
            //   89d0                 | mov                 eax, dword ptr [eax]
            //   01c0                 | mov                 dword ptr [ebp - 0x58], eax

        $sequence_2 = { eb0a c785ecefffff00000000 8b85ecefffff c9 }
            // n = 4, score = 300
            //   eb0a                 | cmp                 dword ptr [ebp - 0x10], eax
            //   c785ecefffff00000000     | jae    0x40
            //   8b85ecefffff         | inc                 dword ptr [ebp - 0x10]
            //   c9                   | inc                 eax

        $sequence_3 = { eb19 e8???????? c70016000000 e8???????? c70016000000 }
            // n = 5, score = 300
            //   eb19                 | mov                 eax, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   c70016000000         | movzx               eax, ax
            //   e8????????           |                     
            //   c70016000000         | mov                 word ptr [ebp - 0x1e], ax

        $sequence_4 = { e8???????? c70016000000 e8???????? c70016000000 83c8ff }
            // n = 5, score = 300
            //   e8????????           |                     
            //   c70016000000         | jmp                 0x664
            //   e8????????           |                     
            //   c70016000000         | cmp                 edx, 0x200
            //   83c8ff               | mov                 eax, dword ptr [eax]

        $sequence_5 = { 89c2 89d0 c1e81f 01d0 }
            // n = 4, score = 300
            //   89c2                 | add                 esp, 0x10
            //   89d0                 | cmp                 eax, -1
            //   c1e81f               | mov                 esi, eax
            //   01d0                 | je                  0x258

        $sequence_6 = { c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff c9 c3 }
            // n = 6, score = 300
            //   c785ecefffff01000000     | mov    dword ptr [esi + 0x24], eax
            //   eb0a                 | mov                 dword ptr [esi + 0x24], eax
            //   c785ecefffff00000000     | movzx    eax, byte ptr [edi + 8]
            //   8b85ecefffff         | movzx               edx, byte ptr [edi + 9]
            //   c9                   | shl                 eax, 8
            //   c3                   | or                  eax, edx

        $sequence_7 = { 83f8ff 750c e8???????? 8b00 83f873 }
            // n = 5, score = 300
            //   83f8ff               | dec                 eax
            //   750c                 | mov                 dword ptr [ebp - 0x1e0], 5
            //   e8????????           |                     
            //   8b00                 | cld                 
            //   83f873               | dec                 eax

        $sequence_8 = { 750c c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff }
            // n = 5, score = 300
            //   750c                 | dec                 eax
            //   c785ecefffff01000000     | sub    ebp, edi
            //   eb0a                 | dec                 eax
            //   c785ecefffff00000000     | test    ebp, ebp
            //   8b85ecefffff         | jle                 0x64

        $sequence_9 = { 750c e8???????? 8b00 83f873 }
            // n = 4, score = 300
            //   750c                 | neg                 esi
            //   e8????????           |                     
            //   8b00                 | mov                 ebp, 1
            //   83f873               | jmp                 0x125

    condition:
        7 of them and filesize < 2310144
}