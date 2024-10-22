rule win_lunchmoney_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lunchmoney."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lunchmoney"
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
        $sequence_0 = { e8???????? 8983b0000000 8b83b0000000 8dbbd4000000 0383ac000000 ba???????? 0383b4000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8983b0000000         | mov                 dword ptr [ebx + 0xb0], eax
            //   8b83b0000000         | mov                 eax, dword ptr [ebx + 0xb0]
            //   8dbbd4000000         | lea                 edi, [ebx + 0xd4]
            //   0383ac000000         | add                 eax, dword ptr [ebx + 0xac]
            //   ba????????           |                     
            //   0383b4000000         | add                 eax, dword ptr [ebx + 0xb4]

        $sequence_1 = { e8???????? c645fc03 8d4dd8 837dec10 8d5598 0f434dd8 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   837dec10             | cmp                 dword ptr [ebp - 0x14], 0x10
            //   8d5598               | lea                 edx, [ebp - 0x68]
            //   0f434dd8             | cmovae              ecx, dword ptr [ebp - 0x28]
            //   e8????????           |                     

        $sequence_2 = { 83e908 8d7608 660fd60f 8d7f08 8b048d786f4000 ffe0 f7c703000000 }
            // n = 7, score = 100
            //   83e908               | sub                 ecx, 8
            //   8d7608               | lea                 esi, [esi + 8]
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d786f4000       | mov                 eax, dword ptr [ecx*4 + 0x406f78]
            //   ffe0                 | jmp                 eax
            //   f7c703000000         | test                edi, 3

        $sequence_3 = { e8???????? 83ec18 c645fc03 8d4520 8965f0 8bcc }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d4520               | lea                 eax, [ebp + 0x20]
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   8bcc                 | mov                 ecx, esp

        $sequence_4 = { 6a00 53 8d4c2438 e8???????? e9???????? bf???????? 57 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   8d4c2438             | lea                 ecx, [esp + 0x38]
            //   e8????????           |                     
            //   e9????????           |                     
            //   bf????????           |                     
            //   57                   | push                edi

        $sequence_5 = { 8d4db4 53 6a01 e8???????? 53 6a01 8d4d9c }
            // n = 7, score = 100
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   e8????????           |                     
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]

        $sequence_6 = { 8d55ec e8???????? 8d55ec 8bc8 e8???????? 8d55ec 8bc8 }
            // n = 7, score = 100
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   e8????????           |                     
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   8bc8                 | mov                 ecx, eax

        $sequence_7 = { 8b8d24e5ffff 8b048550914200 ff3401 ff15???????? 85c0 0f84ee020000 39b53ce5ffff }
            // n = 7, score = 100
            //   8b8d24e5ffff         | mov                 ecx, dword ptr [ebp - 0x1adc]
            //   8b048550914200       | mov                 eax, dword ptr [eax*4 + 0x429150]
            //   ff3401               | push                dword ptr [ecx + eax]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84ee020000         | je                  0x2f4
            //   39b53ce5ffff         | cmp                 dword ptr [ebp - 0x1ac4], esi

        $sequence_8 = { e8???????? 8d4dcc c645fc0b e8???????? 83c430 8d4db4 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   c645fc0b             | mov                 byte ptr [ebp - 4], 0xb
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]

        $sequence_9 = { 7404 6a04 ebed 0fb6c0 }
            // n = 4, score = 100
            //   7404                 | je                  6
            //   6a04                 | push                4
            //   ebed                 | jmp                 0xffffffef
            //   0fb6c0               | movzx               eax, al

    condition:
        7 of them and filesize < 373760
}