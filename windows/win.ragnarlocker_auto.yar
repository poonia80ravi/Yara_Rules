rule win_ragnarlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ragnarlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ragnarlocker"
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
        $sequence_0 = { 50 8d8508ffffff 50 6a00 6a00 6a20 6a00 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   8d8508ffffff         | lea                 eax, [ebp - 0xf8]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a20                 | push                0x20
            //   6a00                 | push                0

        $sequence_1 = { 0bd8 0fb64146 0fa4de08 99 0bf2 c1e308 0bd8 }
            // n = 7, score = 300
            //   0bd8                 | or                  ebx, eax
            //   0fb64146             | movzx               eax, byte ptr [ecx + 0x46]
            //   0fa4de08             | shld                esi, ebx, 8
            //   99                   | cdq                 
            //   0bf2                 | or                  esi, edx
            //   c1e308               | shl                 ebx, 8
            //   0bd8                 | or                  ebx, eax

        $sequence_2 = { 8bd0 137d84 035df8 137dc0 81c33512c725 81d7a706dc9b 015dcc }
            // n = 7, score = 300
            //   8bd0                 | mov                 edx, eax
            //   137d84               | adc                 edi, dword ptr [ebp - 0x7c]
            //   035df8               | add                 ebx, dword ptr [ebp - 8]
            //   137dc0               | adc                 edi, dword ptr [ebp - 0x40]
            //   81c33512c725         | add                 ebx, 0x25c71235
            //   81d7a706dc9b         | adc                 edi, 0x9bdc06a7
            //   015dcc               | add                 dword ptr [ebp - 0x34], ebx

        $sequence_3 = { c1e70e c1ea12 0bfa 8975fc 8b55ec 33df 33f6 }
            // n = 7, score = 300
            //   c1e70e               | shl                 edi, 0xe
            //   c1ea12               | shr                 edx, 0x12
            //   0bfa                 | or                  edi, edx
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   33df                 | xor                 ebx, edi
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { c1e902 f3ab 8bca 83e103 f3aa 0fb64640 88437f }
            // n = 7, score = 300
            //   c1e902               | shr                 ecx, 2
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   0fb64640             | movzx               eax, byte ptr [esi + 0x40]
            //   88437f               | mov                 byte ptr [ebx + 0x7f], al

        $sequence_5 = { 50 ff15???????? 47 897dfc eb03 8b7dfc 83ff40 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   47                   | inc                 edi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   eb03                 | jmp                 5
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   83ff40               | cmp                 edi, 0x40

        $sequence_6 = { 8b9524ffffff 33f6 0bf1 8b8d28ffffff 33de 8b75a4 }
            // n = 6, score = 300
            //   8b9524ffffff         | mov                 edx, dword ptr [ebp - 0xdc]
            //   33f6                 | xor                 esi, esi
            //   0bf1                 | or                  esi, ecx
            //   8b8d28ffffff         | mov                 ecx, dword ptr [ebp - 0xd8]
            //   33de                 | xor                 ebx, esi
            //   8b75a4               | mov                 esi, dword ptr [ebp - 0x5c]

        $sequence_7 = { c1e60e 0bd0 c1e912 8b45bc 0bf1 8b4dc8 33fe }
            // n = 7, score = 300
            //   c1e60e               | shl                 esi, 0xe
            //   0bd0                 | or                  edx, eax
            //   c1e912               | shr                 ecx, 0x12
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   0bf1                 | or                  esi, ecx
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]
            //   33fe                 | xor                 edi, esi

        $sequence_8 = { 8b4ddc 234d0c 8b55e0 33f1 2355fc 8b4df8 33fa }
            // n = 7, score = 300
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   234d0c               | and                 ecx, dword ptr [ebp + 0xc]
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   33f1                 | xor                 esi, ecx
            //   2355fc               | and                 edx, dword ptr [ebp - 4]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   33fa                 | xor                 edi, edx

        $sequence_9 = { 2345f0 8b4dc0 33d0 8b45f8 03c6 13ca 03c3 }
            // n = 7, score = 300
            //   2345f0               | and                 eax, dword ptr [ebp - 0x10]
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]
            //   33d0                 | xor                 edx, eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   03c6                 | add                 eax, esi
            //   13ca                 | adc                 ecx, edx
            //   03c3                 | add                 eax, ebx

    condition:
        7 of them and filesize < 147456
}