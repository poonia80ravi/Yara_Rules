rule win_hlux_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.hlux."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hlux"
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
        $sequence_0 = { 8955e8 894de8 8945e8 53 8b15???????? }
            // n = 5, score = 100
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   53                   | push                ebx
            //   8b15????????         |                     

        $sequence_1 = { 0101 c9 c3 6a10 }
            // n = 4, score = 100
            //   0101                 | add                 dword ptr [ecx], eax
            //   c9                   | leave               
            //   c3                   | ret                 
            //   6a10                 | push                0x10

        $sequence_2 = { 0009 1b4e01 e405 9d }
            // n = 4, score = 100
            //   0009                 | add                 byte ptr [ecx], cl
            //   1b4e01               | sbb                 ecx, dword ptr [esi + 1]
            //   e405                 | in                  al, 5
            //   9d                   | popfd               

        $sequence_3 = { 898564ffffff 8b8d84feffff 898d84feffff 8b0d???????? 8b1d???????? 899d0cffffff 898d64ffffff }
            // n = 7, score = 100
            //   898564ffffff         | mov                 dword ptr [ebp - 0x9c], eax
            //   8b8d84feffff         | mov                 ecx, dword ptr [ebp - 0x17c]
            //   898d84feffff         | mov                 dword ptr [ebp - 0x17c], ecx
            //   8b0d????????         |                     
            //   8b1d????????         |                     
            //   899d0cffffff         | mov                 dword ptr [ebp - 0xf4], ebx
            //   898d64ffffff         | mov                 dword ptr [ebp - 0x9c], ecx

        $sequence_4 = { 0000 008365f0fe8b 4d 0883c108e918 }
            // n = 4, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   008365f0fe8b         | add                 byte ptr [ebx - 0x74010f9b], al
            //   4d                   | dec                 ebp
            //   0883c108e918         | or                  byte ptr [ebx + 0x18e908c1], al

        $sequence_5 = { 0130 8b13 8b08 85d2 }
            // n = 4, score = 100
            //   0130                 | add                 dword ptr [eax], esi
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   85d2                 | test                edx, edx

        $sequence_6 = { b9ab8f22ff 8955c8 83f9df 0f85cc000000 33f6 81fe230cbf1a }
            // n = 6, score = 100
            //   b9ab8f22ff           | mov                 ecx, 0xff228fab
            //   8955c8               | mov                 dword ptr [ebp - 0x38], edx
            //   83f9df               | cmp                 ecx, -0x21
            //   0f85cc000000         | jne                 0xd2
            //   33f6                 | xor                 esi, esi
            //   81fe230cbf1a         | cmp                 esi, 0x1abf0c23

        $sequence_7 = { 81fbb00763db 0f855d010000 81fb851b125f 0f8451010000 8985a4feffff }
            // n = 5, score = 100
            //   81fbb00763db         | cmp                 ebx, 0xdb6307b0
            //   0f855d010000         | jne                 0x163
            //   81fb851b125f         | cmp                 ebx, 0x5f121b85
            //   0f8451010000         | je                  0x157
            //   8985a4feffff         | mov                 dword ptr [ebp - 0x15c], eax

        $sequence_8 = { 010f 840f 0000 008365f0fe8b }
            // n = 4, score = 100
            //   010f                 | add                 dword ptr [edi], ecx
            //   840f                 | test                byte ptr [edi], cl
            //   0000                 | add                 byte ptr [eax], al
            //   008365f0fe8b         | add                 byte ptr [ebx - 0x74010f9b], al

        $sequence_9 = { 7406 89b51cffffff 8b9d84feffff 8b05???????? 8945d8 }
            // n = 5, score = 100
            //   7406                 | je                  8
            //   89b51cffffff         | mov                 dword ptr [ebp - 0xe4], esi
            //   8b9d84feffff         | mov                 ebx, dword ptr [ebp - 0x17c]
            //   8b05????????         |                     
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax

        $sequence_10 = { 0088aa4b0023 d18a0688078a 46 018847018a46 }
            // n = 4, score = 100
            //   0088aa4b0023         | add                 byte ptr [eax + 0x23004baa], cl
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi
            //   018847018a46         | add                 dword ptr [eax + 0x468a0147], ecx

        $sequence_11 = { 85c9 0f84f9000000 8b1d???????? 8b45bc 85c0 0f85e8000000 }
            // n = 6, score = 100
            //   85c9                 | test                ecx, ecx
            //   0f84f9000000         | je                  0xff
            //   8b1d????????         |                     
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   85c0                 | test                eax, eax
            //   0f85e8000000         | jne                 0xee

        $sequence_12 = { 09f6 0f8486000000 83fe51 0f857d000000 }
            // n = 4, score = 100
            //   09f6                 | or                  esi, esi
            //   0f8486000000         | je                  0x8c
            //   83fe51               | cmp                 esi, 0x51
            //   0f857d000000         | jne                 0x83

        $sequence_13 = { 0104bb 8d1447 89542418 e9???????? }
            // n = 4, score = 100
            //   0104bb               | add                 dword ptr [ebx + edi*4], eax
            //   8d1447               | lea                 edx, [edi + eax*2]
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   e9????????           |                     

        $sequence_14 = { 8b0d???????? 83fbd3 0f8596020000 21db 0f858e020000 81fb91ba2083 0f8482020000 }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   83fbd3               | cmp                 ebx, -0x2d
            //   0f8596020000         | jne                 0x29c
            //   21db                 | and                 ebx, ebx
            //   0f858e020000         | jne                 0x294
            //   81fb91ba2083         | cmp                 ebx, 0x8320ba91
            //   0f8482020000         | je                  0x288

        $sequence_15 = { 0104b9 33c9 83c408 85c0 }
            // n = 4, score = 100
            //   0104b9               | add                 dword ptr [ecx + edi*4], eax
            //   33c9                 | xor                 ecx, ecx
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 3147776
}