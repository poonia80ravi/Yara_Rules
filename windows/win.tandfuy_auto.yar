rule win_tandfuy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.tandfuy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tandfuy"
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
        $sequence_0 = { e8???????? eb0c 8d85d8f5ffff 50 e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   eb0c                 | jmp                 0xe
            //   8d85d8f5ffff         | lea                 eax, [ebp - 0xa28]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_1 = { 89542438 8b542420 57 53 6800000002 52 }
            // n = 6, score = 100
            //   89542438             | mov                 dword ptr [esp + 0x38], edx
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   57                   | push                edi
            //   53                   | push                ebx
            //   6800000002           | push                0x2000000
            //   52                   | push                edx

        $sequence_2 = { 8079ff00 0f8547ffffff 8bc6 808821eb6e0008 40 }
            // n = 5, score = 100
            //   8079ff00             | cmp                 byte ptr [ecx - 1], 0
            //   0f8547ffffff         | jne                 0xffffff4d
            //   8bc6                 | mov                 eax, esi
            //   808821eb6e0008       | or                  byte ptr [eax + 0x6eeb21], 8
            //   40                   | inc                 eax

        $sequence_3 = { 81ecb4020000 53 56 57 8965e8 8d8554fdffff }
            // n = 6, score = 100
            //   81ecb4020000         | sub                 esp, 0x2b4
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   8d8554fdffff         | lea                 eax, [ebp - 0x2ac]

        $sequence_4 = { 8bf8 83ffff 741e 8d542414 }
            // n = 4, score = 100
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1
            //   741e                 | je                  0x20
            //   8d542414             | lea                 edx, [esp + 0x14]

        $sequence_5 = { 3b35???????? 7338 8bce 8bc6 c1f905 83e01f 8b0c8d60fc6e00 }
            // n = 7, score = 100
            //   3b35????????         |                     
            //   7338                 | jae                 0x3a
            //   8bce                 | mov                 ecx, esi
            //   8bc6                 | mov                 eax, esi
            //   c1f905               | sar                 ecx, 5
            //   83e01f               | and                 eax, 0x1f
            //   8b0c8d60fc6e00       | mov                 ecx, dword ptr [ecx*4 + 0x6efc60]

        $sequence_6 = { ff249548646e00 8bc7 ba03000000 83e904 720c 83e003 }
            // n = 6, score = 100
            //   ff249548646e00       | jmp                 dword ptr [edx*4 + 0x6e6448]
            //   8bc7                 | mov                 eax, edi
            //   ba03000000           | mov                 edx, 3
            //   83e904               | sub                 ecx, 4
            //   720c                 | jb                  0xe
            //   83e003               | and                 eax, 3

        $sequence_7 = { 83c408 85c0 7418 8b5c2418 3bf3 7412 }
            // n = 6, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7418                 | je                  0x1a
            //   8b5c2418             | mov                 ebx, dword ptr [esp + 0x18]
            //   3bf3                 | cmp                 esi, ebx
            //   7412                 | je                  0x14

        $sequence_8 = { c3 33c0 6888130000 89442426 }
            // n = 4, score = 100
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   6888130000           | push                0x1388
            //   89442426             | mov                 dword ptr [esp + 0x26], eax

        $sequence_9 = { b911000000 33c0 8d7c244c 8954243c }
            // n = 4, score = 100
            //   b911000000           | mov                 ecx, 0x11
            //   33c0                 | xor                 eax, eax
            //   8d7c244c             | lea                 edi, [esp + 0x4c]
            //   8954243c             | mov                 dword ptr [esp + 0x3c], edx

    condition:
        7 of them and filesize < 155648
}