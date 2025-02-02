rule win_makadocs_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.makadocs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.makadocs"
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
        $sequence_0 = { 51 c784248400000001000000 8bc4 89642420 50 b9???????? e8???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   c784248400000001000000     | mov    dword ptr [esp + 0x84], 1
            //   8bc4                 | mov                 eax, esp
            //   89642420             | mov                 dword ptr [esp + 0x20], esp
            //   50                   | push                eax
            //   b9????????           |                     
            //   e8????????           |                     

        $sequence_1 = { 89742418 8d542410 52 b9???????? c644243402 }
            // n = 5, score = 100
            //   89742418             | mov                 dword ptr [esp + 0x18], esi
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   52                   | push                edx
            //   b9????????           |                     
            //   c644243402           | mov                 byte ptr [esp + 0x34], 2

        $sequence_2 = { e8???????? 83c408 c64424680e 8b5c2470 e8???????? c644246802 8b44243c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c64424680e           | mov                 byte ptr [esp + 0x68], 0xe
            //   8b5c2470             | mov                 ebx, dword ptr [esp + 0x70]
            //   e8????????           |                     
            //   c644246802           | mov                 byte ptr [esp + 0x68], 2
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]

        $sequence_3 = { b9???????? ffd0 83c010 89442430 c68424a400000007 8b15???????? }
            // n = 6, score = 100
            //   b9????????           |                     
            //   ffd0                 | call                eax
            //   83c010               | add                 eax, 0x10
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   c68424a400000007     | mov                 byte ptr [esp + 0xa4], 7
            //   8b15????????         |                     

        $sequence_4 = { 8b742428 51 8b4ef0 8b11 8b4210 83c6f0 89642430 }
            // n = 7, score = 100
            //   8b742428             | mov                 esi, dword ptr [esp + 0x28]
            //   51                   | push                ecx
            //   8b4ef0               | mov                 ecx, dword ptr [esi - 0x10]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b4210               | mov                 eax, dword ptr [edx + 0x10]
            //   83c6f0               | add                 esi, -0x10
            //   89642430             | mov                 dword ptr [esp + 0x30], esp

        $sequence_5 = { e8???????? 6a0a 8d4c2434 51 56 89755c e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a0a                 | push                0xa
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   89755c               | mov                 dword ptr [ebp + 0x5c], esi
            //   e8????????           |                     

        $sequence_6 = { 03c0 99 83c404 01442444 11542448 eb44 53 }
            // n = 7, score = 100
            //   03c0                 | add                 eax, eax
            //   99                   | cdq                 
            //   83c404               | add                 esp, 4
            //   01442444             | add                 dword ptr [esp + 0x44], eax
            //   11542448             | adc                 dword ptr [esp + 0x48], edx
            //   eb44                 | jmp                 0x46
            //   53                   | push                ebx

        $sequence_7 = { eb06 8b00 ebef 33c0 3b700c 7305 }
            // n = 6, score = 100
            //   eb06                 | jmp                 8
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ebef                 | jmp                 0xfffffff1
            //   33c0                 | xor                 eax, eax
            //   3b700c               | cmp                 esi, dword ptr [eax + 0xc]
            //   7305                 | jae                 7

        $sequence_8 = { 8bd4 89642420 52 8d4c2430 e8???????? 51 899c2484000000 }
            // n = 7, score = 100
            //   8bd4                 | mov                 edx, esp
            //   89642420             | mov                 dword ptr [esp + 0x20], esp
            //   52                   | push                edx
            //   8d4c2430             | lea                 ecx, [esp + 0x30]
            //   e8????????           |                     
            //   51                   | push                ecx
            //   899c2484000000       | mov                 dword ptr [esp + 0x84], ebx

        $sequence_9 = { 8b08 8b742414 8d41f0 83c6f0 3bc6 7446 }
            // n = 6, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   8d41f0               | lea                 eax, [ecx - 0x10]
            //   83c6f0               | add                 esi, -0x10
            //   3bc6                 | cmp                 eax, esi
            //   7446                 | je                  0x48

    condition:
        7 of them and filesize < 344064
}