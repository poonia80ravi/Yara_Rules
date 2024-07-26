rule win_phobos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.phobos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
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
        $sequence_0 = { 891a 8365fc00 8a0b 56 8d7301 eb03 }
            // n = 6, score = 100
            //   891a                 | mov                 dword ptr [edx], ebx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8a0b                 | mov                 cl, byte ptr [ebx]
            //   56                   | push                esi
            //   8d7301               | lea                 esi, [ebx + 1]
            //   eb03                 | jmp                 5

        $sequence_1 = { 6a16 8944243c e8???????? 57 6a23 89442428 e8???????? }
            // n = 7, score = 100
            //   6a16                 | push                0x16
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   e8????????           |                     
            //   57                   | push                edi
            //   6a23                 | push                0x23
            //   89442428             | mov                 dword ptr [esp + 0x28], eax
            //   e8????????           |                     

        $sequence_2 = { a1???????? 83c424 8945c8 a1???????? 56 6a0d 8945cc }
            // n = 7, score = 100
            //   a1????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   a1????????           |                     
            //   56                   | push                esi
            //   6a0d                 | push                0xd
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax

        $sequence_3 = { f7d8 1bc0 83c02c 50 e8???????? 59 59 }
            // n = 7, score = 100
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83c02c               | add                 eax, 0x2c
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_4 = { 85c0 0f84bb000000 8b4d10 8bdf 8d78ff c1ef04 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   0f84bb000000         | je                  0xc1
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8bdf                 | mov                 ebx, edi
            //   8d78ff               | lea                 edi, [eax - 1]
            //   c1ef04               | shr                 edi, 4

        $sequence_5 = { ff7620 ff75f8 ff15???????? 85c0 0f844e010000 8b45fc 3945d4 }
            // n = 7, score = 100
            //   ff7620               | push                dword ptr [esi + 0x20]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f844e010000         | je                  0x154
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   3945d4               | cmp                 dword ptr [ebp - 0x2c], eax

        $sequence_6 = { 8b5d10 56 57 be???????? 8d7dfc 66a5 }
            // n = 6, score = 100
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   56                   | push                esi
            //   57                   | push                edi
            //   be????????           |                     
            //   8d7dfc               | lea                 edi, [ebp - 4]
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]

        $sequence_7 = { 8bf3 85db 75e8 215f20 215f04 5b 5e }
            // n = 7, score = 100
            //   8bf3                 | mov                 esi, ebx
            //   85db                 | test                ebx, ebx
            //   75e8                 | jne                 0xffffffea
            //   215f20               | and                 dword ptr [edi + 0x20], ebx
            //   215f04               | and                 dword ptr [edi + 4], ebx
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_8 = { e8???????? 6a00 6a14 89442420 e8???????? be???????? 8d7c2428 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a14                 | push                0x14
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     
            //   be????????           |                     
            //   8d7c2428             | lea                 edi, [esp + 0x28]

        $sequence_9 = { 8b4508 8b5808 85db 0f84b7000000 83650800 8bfb eb3f }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b5808               | mov                 ebx, dword ptr [eax + 8]
            //   85db                 | test                ebx, ebx
            //   0f84b7000000         | je                  0xbd
            //   83650800             | and                 dword ptr [ebp + 8], 0
            //   8bfb                 | mov                 edi, ebx
            //   eb3f                 | jmp                 0x41

    condition:
        7 of them and filesize < 139264
}