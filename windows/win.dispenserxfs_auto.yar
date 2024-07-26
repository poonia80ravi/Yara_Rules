rule win_dispenserxfs_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.dispenserxfs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dispenserxfs"
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
        $sequence_0 = { 8945e0 33c0 66898574feffff 8d45f8 898578feffff 6a06 58 }
            // n = 7, score = 200
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   33c0                 | xor                 eax, eax
            //   66898574feffff       | mov                 word ptr [ebp - 0x18c], ax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   898578feffff         | mov                 dword ptr [ebp - 0x188], eax
            //   6a06                 | push                6
            //   58                   | pop                 eax

        $sequence_1 = { 66898d4afeffff 8945cc 8d851bfeffff 8945e0 }
            // n = 4, score = 200
            //   66898d4afeffff       | mov                 word ptr [ebp - 0x1b6], cx
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8d851bfeffff         | lea                 eax, [ebp - 0x1e5]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax

        $sequence_2 = { 0f86f1000000 56 8b35???????? 6800040000 }
            // n = 4, score = 200
            //   0f86f1000000         | jbe                 0xf7
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6800040000           | push                0x400

        $sequence_3 = { 8975bc 8975c0 8975c4 8b35???????? 50 }
            // n = 5, score = 200
            //   8975bc               | mov                 dword ptr [ebp - 0x44], esi
            //   8975c0               | mov                 dword ptr [ebp - 0x40], esi
            //   8975c4               | mov                 dword ptr [ebp - 0x3c], esi
            //   8b35????????         |                     
            //   50                   | push                eax

        $sequence_4 = { 8d8544fdffff 56 33f6 8945f8 43 898d44fdffff }
            // n = 6, score = 200
            //   8d8544fdffff         | lea                 eax, [ebp - 0x2bc]
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   43                   | inc                 ebx
            //   898d44fdffff         | mov                 dword ptr [ebp - 0x2bc], ecx

        $sequence_5 = { ffd6 8d8548feffff 83c418 89852cfdffff 8d8588feffff 898530fdffff 8d85c8feffff }
            // n = 7, score = 200
            //   ffd6                 | call                esi
            //   8d8548feffff         | lea                 eax, [ebp - 0x1b8]
            //   83c418               | add                 esp, 0x18
            //   89852cfdffff         | mov                 dword ptr [ebp - 0x2d4], eax
            //   8d8588feffff         | lea                 eax, [ebp - 0x178]
            //   898530fdffff         | mov                 dword ptr [ebp - 0x2d0], eax
            //   8d85c8feffff         | lea                 eax, [ebp - 0x138]

        $sequence_6 = { 83600300 8b45f6 83600d00 8d45fc 50 6860ea0000 8d45ec }
            // n = 7, score = 200
            //   83600300             | and                 dword ptr [eax + 3], 0
            //   8b45f6               | mov                 eax, dword ptr [ebp - 0xa]
            //   83600d00             | and                 dword ptr [eax + 0xd], 0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6860ea0000           | push                0xea60
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_7 = { 50 8d8555ffffff 50 ffd6 68???????? }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8d8555ffffff         | lea                 eax, [ebp - 0xab]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   68????????           |                     

        $sequence_8 = { 0f84ab000000 68???????? e8???????? 59 57 53 56 }
            // n = 7, score = 200
            //   0f84ab000000         | je                  0xb1
            //   68????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   57                   | push                edi
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_9 = { 40 663b432e 8945f0 0f8239ffffff 8b4df4 8b45e4 }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   663b432e             | cmp                 ax, word ptr [ebx + 0x2e]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   0f8239ffffff         | jb                  0xffffff3f
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

    condition:
        7 of them and filesize < 114688
}