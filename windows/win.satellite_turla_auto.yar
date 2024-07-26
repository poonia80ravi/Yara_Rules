rule win_satellite_turla_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.satellite_turla."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satellite_turla"
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
        $sequence_0 = { 0108 833e00 7c1f 8b542410 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7c1f                 | jl                  0x21
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

        $sequence_1 = { 0105???????? 83c410 29442418 75a9 }
            // n = 4, score = 200
            //   0105????????         |                     
            //   83c410               | add                 esp, 0x10
            //   29442418             | sub                 dword ptr [esp + 0x18], eax
            //   75a9                 | jne                 0xffffffab

        $sequence_2 = { 0108 833e00 7fc7 db46fc }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7fc7                 | jg                  0xffffffc9
            //   db46fc               | fild                dword ptr [esi - 4]

        $sequence_3 = { 0108 833a00 7c23 8b442428 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833a00               | cmp                 dword ptr [edx], 0
            //   7c23                 | jl                  0x25
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]

        $sequence_4 = { 0105???????? 81c3b0020000 2945e0 75ae 837dd400 }
            // n = 5, score = 200
            //   0105????????         |                     
            //   81c3b0020000         | add                 ebx, 0x2b0
            //   2945e0               | sub                 dword ptr [ebp - 0x20], eax
            //   75ae                 | jne                 0xffffffb0
            //   837dd400             | cmp                 dword ptr [ebp - 0x2c], 0

        $sequence_5 = { 0108 833e00 7cc7 7e39 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7cc7                 | jl                  0xffffffc9
            //   7e39                 | jle                 0x3b

        $sequence_6 = { 51 8d9424b8030000 68???????? 52 ff15???????? 8b54242c }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   8d9424b8030000       | lea                 edx, [esp + 0x3b8]
            //   68????????           |                     
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]

        $sequence_7 = { 0105???????? 83c410 29442420 75aa }
            // n = 4, score = 200
            //   0105????????         |                     
            //   83c410               | add                 esp, 0x10
            //   29442420             | sub                 dword ptr [esp + 0x20], eax
            //   75aa                 | jne                 0xffffffac

        $sequence_8 = { 68???????? 50 ffd7 8d85f0feffff 50 }
            // n = 5, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax

        $sequence_9 = { 50 c645a82d c645a90f c645aa1e c645ab29 c645ac05 c645ad07 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c645a82d             | mov                 byte ptr [ebp - 0x58], 0x2d
            //   c645a90f             | mov                 byte ptr [ebp - 0x57], 0xf
            //   c645aa1e             | mov                 byte ptr [ebp - 0x56], 0x1e
            //   c645ab29             | mov                 byte ptr [ebp - 0x55], 0x29
            //   c645ac05             | mov                 byte ptr [ebp - 0x54], 5
            //   c645ad07             | mov                 byte ptr [ebp - 0x53], 7

        $sequence_10 = { 50 56 ff15???????? 8d45e8 50 56 ff15???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_11 = { ffd6 a3???????? 6a0d 8d45e8 6a0a }
            // n = 5, score = 100
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   6a0d                 | push                0xd
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   6a0a                 | push                0xa

        $sequence_12 = { ff15???????? 6a40 8bf0 33db 59 33c0 8dbdedfdffff }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   6a40                 | push                0x40
            //   8bf0                 | mov                 esi, eax
            //   33db                 | xor                 ebx, ebx
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   8dbdedfdffff         | lea                 edi, [ebp - 0x213]

        $sequence_13 = { e8???????? 83c40c 8d45d0 885ddb }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   885ddb               | mov                 byte ptr [ebp - 0x25], bl

        $sequence_14 = { 85c0 0f8400010000 895dfc 53 6880000000 6a03 53 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f8400010000         | je                  0x106
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   53                   | push                ebx
            //   6880000000           | push                0x80
            //   6a03                 | push                3
            //   53                   | push                ebx

        $sequence_15 = { 6a01 3206 88450f 8d450f 50 56 e8???????? }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   3206                 | xor                 al, byte ptr [esi]
            //   88450f               | mov                 byte ptr [ebp + 0xf], al
            //   8d450f               | lea                 eax, [ebp + 0xf]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1040384
}