rule win_shimrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.shimrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shimrat"
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
        $sequence_0 = { 33db 43 53 57 8d4514 50 }
            // n = 6, score = 100
            //   33db                 | xor                 ebx, ebx
            //   43                   | inc                 ebx
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8d4514               | lea                 eax, [ebp + 0x14]
            //   50                   | push                eax

        $sequence_1 = { 50 e8???????? 83c40c 56 8d85bce7ffff 50 8d4d24 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   56                   | push                esi
            //   8d85bce7ffff         | lea                 eax, [ebp - 0x1844]
            //   50                   | push                eax
            //   8d4d24               | lea                 ecx, [ebp + 0x24]

        $sequence_2 = { e8???????? 40 50 e8???????? 8bd0 57 8916 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   57                   | push                edi
            //   8916                 | mov                 dword ptr [esi], edx

        $sequence_3 = { e8???????? 83e80c 50 6a08 8d45e8 50 8d4d08 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83e80c               | sub                 eax, 0xc
            //   50                   | push                eax
            //   6a08                 | push                8
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   8d4d08               | lea                 ecx, [ebp + 8]

        $sequence_4 = { 50 8d4d18 e8???????? 8d4dbc }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8d4d18               | lea                 ecx, [ebp + 0x18]
            //   e8????????           |                     
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]

        $sequence_5 = { 53 8d45e8 56 50 e8???????? 6a03 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a03                 | push                3

        $sequence_6 = { 59 ff74240c e8???????? 8bf8 }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_7 = { c21000 55 8d6c248c 81ec98040000 53 }
            // n = 5, score = 100
            //   c21000               | ret                 0x10
            //   55                   | push                ebp
            //   8d6c248c             | lea                 ebp, [esp - 0x74]
            //   81ec98040000         | sub                 esp, 0x498
            //   53                   | push                ebx

        $sequence_8 = { 837dd406 7513 8d8550ffffff 68???????? }
            // n = 4, score = 100
            //   837dd406             | cmp                 dword ptr [ebp - 0x2c], 6
            //   7513                 | jne                 0x15
            //   8d8550ffffff         | lea                 eax, [ebp - 0xb0]
            //   68????????           |                     

        $sequence_9 = { 8bd9 8d4d5c 66a5 e8???????? 8d455c 50 }
            // n = 6, score = 100
            //   8bd9                 | mov                 ebx, ecx
            //   8d4d5c               | lea                 ecx, [ebp + 0x5c]
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   e8????????           |                     
            //   8d455c               | lea                 eax, [ebp + 0x5c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 65536
}