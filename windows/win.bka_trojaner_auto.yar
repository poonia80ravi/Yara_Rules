rule win_bka_trojaner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bka_trojaner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bka_trojaner"
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
        $sequence_0 = { 6a00 51 8bf1 8bcc 89642418 68???????? }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8bf1                 | mov                 esi, ecx
            //   8bcc                 | mov                 ecx, esp
            //   89642418             | mov                 dword ptr [esp + 0x18], esp
            //   68????????           |                     

        $sequence_1 = { 83c40c c3 2da4030000 7422 83e804 7417 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   c3                   | ret                 
            //   2da4030000           | sub                 eax, 0x3a4
            //   7422                 | je                  0x24
            //   83e804               | sub                 eax, 4
            //   7417                 | je                  0x19

        $sequence_2 = { 51 57 e8???????? 8bf0 ff15???????? 85f6 89442408 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   57                   | push                edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   85f6                 | test                esi, esi
            //   89442408             | mov                 dword ptr [esp + 8], eax

        $sequence_3 = { 8d4c2420 51 52 ff15???????? 8b442420 8b4c2424 8b542428 }
            // n = 7, score = 100
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]

        $sequence_4 = { 5f 5e 5d 33c0 5b 8b4c2460 e8???????? }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   8b4c2460             | mov                 ecx, dword ptr [esp + 0x60]
            //   e8????????           |                     

        $sequence_5 = { ff248520304000 8b8c2484000000 8b11 8b442478 }
            // n = 4, score = 100
            //   ff248520304000       | jmp                 dword ptr [eax*4 + 0x403020]
            //   8b8c2484000000       | mov                 ecx, dword ptr [esp + 0x84]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b442478             | mov                 eax, dword ptr [esp + 0x78]

        $sequence_6 = { 8d442458 50 ff15???????? 8b35???????? 68???????? 8d4c2458 }
            // n = 6, score = 100
            //   8d442458             | lea                 eax, [esp + 0x58]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   68????????           |                     
            //   8d4c2458             | lea                 ecx, [esp + 0x58]

        $sequence_7 = { 6a01 68???????? ffd3 85c0 0f857afeffff 393cb5f0ea4000 742e }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   68????????           |                     
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   0f857afeffff         | jne                 0xfffffe80
            //   393cb5f0ea4000       | cmp                 dword ptr [esi*4 + 0x40eaf0], edi
            //   742e                 | je                  0x30

        $sequence_8 = { 52 6aeb 50 ff15???????? 5f 5e 5d }
            // n = 7, score = 100
            //   52                   | push                edx
            //   6aeb                 | push                -0x15
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_9 = { 85c9 8bd1 7e13 8d048decea4000 3938 }
            // n = 5, score = 100
            //   85c9                 | test                ecx, ecx
            //   8bd1                 | mov                 edx, ecx
            //   7e13                 | jle                 0x15
            //   8d048decea4000       | lea                 eax, [ecx*4 + 0x40eaec]
            //   3938                 | cmp                 dword ptr [eax], edi

    condition:
        7 of them and filesize < 221184
}