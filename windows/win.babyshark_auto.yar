rule win_babyshark_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.babyshark."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.babyshark"
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
        $sequence_0 = { 83c40c 8d4c2404 6a00 51 ffd6 6a00 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   6a00                 | push                0

        $sequence_1 = { 8bc8 83e01f c1f905 8b0c8d607e4000 8a44c104 83e040 }
            // n = 6, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d607e4000       | mov                 ecx, dword ptr [ecx*4 + 0x407e60]
            //   8a44c104             | mov                 al, byte ptr [ecx + eax*8 + 4]
            //   83e040               | and                 eax, 0x40

        $sequence_2 = { 8b0c8d607e4000 8a44c104 83e040 c3 a1???????? }
            // n = 5, score = 100
            //   8b0c8d607e4000       | mov                 ecx, dword ptr [ecx*4 + 0x407e60]
            //   8a44c104             | mov                 al, byte ptr [ecx + eax*8 + 4]
            //   83e040               | and                 eax, 0x40
            //   c3                   | ret                 
            //   a1????????           |                     

        $sequence_3 = { bf???????? f3ab 8d3452 895dfc c1e604 aa 8d9ec8674000 }
            // n = 7, score = 100
            //   bf????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d3452               | lea                 esi, [edx + edx*2]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   c1e604               | shl                 esi, 4
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d9ec8674000         | lea                 ebx, [esi + 0x4067c8]

        $sequence_4 = { 80e920 ebe0 80a0206c400000 40 3bc6 72be 5e }
            // n = 7, score = 100
            //   80e920               | sub                 cl, 0x20
            //   ebe0                 | jmp                 0xffffffe2
            //   80a0206c400000       | and                 byte ptr [eax + 0x406c20], 0
            //   40                   | inc                 eax
            //   3bc6                 | cmp                 eax, esi
            //   72be                 | jb                  0xffffffc0
            //   5e                   | pop                 esi

        $sequence_5 = { 8db6bc674000 bf???????? a5 a5 59 a3???????? }
            // n = 6, score = 100
            //   8db6bc674000         | lea                 esi, [esi + 0x4067bc]
            //   bf????????           |                     
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   59                   | pop                 ecx
            //   a3????????           |                     

        $sequence_6 = { 8a8094504000 83e00f eb02 33c0 0fbe84c6b4504000 }
            // n = 5, score = 100
            //   8a8094504000         | mov                 al, byte ptr [eax + 0x405094]
            //   83e00f               | and                 eax, 0xf
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   0fbe84c6b4504000     | movsx               eax, byte ptr [esi + eax*8 + 0x4050b4]

        $sequence_7 = { c1f804 83f807 8945d0 0f879a060000 ff2485271a4000 834df0ff }
            // n = 6, score = 100
            //   c1f804               | sar                 eax, 4
            //   83f807               | cmp                 eax, 7
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   0f879a060000         | ja                  0x6a0
            //   ff2485271a4000       | jmp                 dword ptr [eax*4 + 0x401a27]
            //   834df0ff             | or                  dword ptr [ebp - 0x10], 0xffffffff

        $sequence_8 = { 5e 8d0c8dc8614000 3bc1 7304 3910 7402 }
            // n = 6, score = 100
            //   5e                   | pop                 esi
            //   8d0c8dc8614000       | lea                 ecx, [ecx*4 + 0x4061c8]
            //   3bc1                 | cmp                 eax, ecx
            //   7304                 | jae                 6
            //   3910                 | cmp                 dword ptr [eax], edx
            //   7402                 | je                  4

        $sequence_9 = { ff15???????? 8bf0 68???????? 8d442408 68???????? 50 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   68????????           |                     
            //   8d442408             | lea                 eax, [esp + 8]
            //   68????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 65272
}