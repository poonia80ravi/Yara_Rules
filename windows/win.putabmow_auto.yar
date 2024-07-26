rule win_putabmow_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.putabmow."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.putabmow"
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
        $sequence_0 = { ed 004104 ee 004704 ee 004d04 ee }
            // n = 7, score = 100
            //   ed                   | in                  eax, dx
            //   004104               | add                 byte ptr [ecx + 4], al
            //   ee                   | out                 dx, al
            //   004704               | add                 byte ptr [edi + 4], al
            //   ee                   | out                 dx, al
            //   004d04               | add                 byte ptr [ebp + 4], cl
            //   ee                   | out                 dx, al

        $sequence_1 = { 8bc6 23cb 23c7 0bc8 83c404 8b524c }
            // n = 6, score = 100
            //   8bc6                 | mov                 eax, esi
            //   23cb                 | and                 ecx, ebx
            //   23c7                 | and                 eax, edi
            //   0bc8                 | or                  ecx, eax
            //   83c404               | add                 esp, 4
            //   8b524c               | mov                 edx, dword ptr [edx + 0x4c]

        $sequence_2 = { 83c404 c74424440f000000 8bc6 c744244000000000 c644243000 8b4c2468 64890d00000000 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   c74424440f000000     | mov                 dword ptr [esp + 0x44], 0xf
            //   8bc6                 | mov                 eax, esi
            //   c744244000000000     | mov                 dword ptr [esp + 0x40], 0
            //   c644243000           | mov                 byte ptr [esp + 0x30], 0
            //   8b4c2468             | mov                 ecx, dword ptr [esp + 0x68]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_3 = { 03f9 00f5 03f9 000e 04f9 000e 04f9 }
            // n = 7, score = 100
            //   03f9                 | add                 edi, ecx
            //   00f5                 | add                 ch, dh
            //   03f9                 | add                 edi, ecx
            //   000e                 | add                 byte ptr [esi], cl
            //   04f9                 | add                 al, 0xf9
            //   000e                 | add                 byte ptr [esi], cl
            //   04f9                 | add                 al, 0xf9

        $sequence_4 = { 5e c3 2bf8 57 50 e8???????? 83c408 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   2bf8                 | sub                 edi, eax
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_5 = { 8d9b00000000 8b02 3b01 7518 8b442414 83c204 83c104 }
            // n = 7, score = 100
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   3b01                 | cmp                 eax, dword ptr [ecx]
            //   7518                 | jne                 0x1a
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   83c204               | add                 edx, 4
            //   83c104               | add                 ecx, 4

        $sequence_6 = { 05ed00f505 ed 00f5 05ed00f505 fb 0015???????? 05fb002305 }
            // n = 7, score = 100
            //   05ed00f505           | add                 eax, 0x5f500ed
            //   ed                   | in                  eax, dx
            //   00f5                 | add                 ch, dh
            //   05ed00f505           | add                 eax, 0x5f500ed
            //   fb                   | sti                 
            //   0015????????         |                     
            //   05fb002305           | add                 eax, 0x52300fb

        $sequence_7 = { e9???????? 8b45b0 83fe02 756a 8b55b4 f7c200000002 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   8b45b0               | mov                 eax, dword ptr [ebp - 0x50]
            //   83fe02               | cmp                 esi, 2
            //   756a                 | jne                 0x6c
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]
            //   f7c200000002         | test                edx, 0x2000000

        $sequence_8 = { 8b4dec 83c114 e9???????? 8b4df0 83c120 e9???????? 8b542408 }
            // n = 7, score = 100
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   83c114               | add                 ecx, 0x14
            //   e9????????           |                     
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   83c120               | add                 ecx, 0x20
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]

        $sequence_9 = { 50 8d842450060000 50 c68424480b00005f 8bcb e8???????? eb02 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d842450060000       | lea                 eax, [esp + 0x650]
            //   50                   | push                eax
            //   c68424480b00005f     | mov                 byte ptr [esp + 0xb48], 0x5f
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   eb02                 | jmp                 4

    condition:
        7 of them and filesize < 704512
}