rule win_cheesetray_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.cheesetray."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cheesetray"
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
        $sequence_0 = { 8d44243e 33d2 53 50 6689542444 e8???????? 8b8c24a4000000 }
            // n = 7, score = 200
            //   8d44243e             | lea                 eax, [esp + 0x3e]
            //   33d2                 | xor                 edx, edx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   6689542444           | mov                 word ptr [esp + 0x44], dx
            //   e8????????           |                     
            //   8b8c24a4000000       | mov                 ecx, dword ptr [esp + 0xa4]

        $sequence_1 = { 81fb00300000 750b 8b5d10 25ff0f0000 011c38 8b4104 83e808 }
            // n = 7, score = 200
            //   81fb00300000         | cmp                 ebx, 0x3000
            //   750b                 | jne                 0xd
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   25ff0f0000           | and                 eax, 0xfff
            //   011c38               | add                 dword ptr [eax + edi], ebx
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   83e808               | sub                 eax, 8

        $sequence_2 = { c744242477006100 c74424286c006c00 c744242c20006400 c744243065006c00 c744243465007400 c744243865002000 c744243c70006f00 }
            // n = 7, score = 200
            //   c744242477006100     | mov                 dword ptr [esp + 0x24], 0x610077
            //   c74424286c006c00     | mov                 dword ptr [esp + 0x28], 0x6c006c
            //   c744242c20006400     | mov                 dword ptr [esp + 0x2c], 0x640020
            //   c744243065006c00     | mov                 dword ptr [esp + 0x30], 0x6c0065
            //   c744243465007400     | mov                 dword ptr [esp + 0x34], 0x740065
            //   c744243865002000     | mov                 dword ptr [esp + 0x38], 0x200065
            //   c744243c70006f00     | mov                 dword ptr [esp + 0x3c], 0x6f0070

        $sequence_3 = { 668985e8fdffff e8???????? 83c40c 6a3a 56 e8???????? 8bf0 }
            // n = 7, score = 200
            //   668985e8fdffff       | mov                 word ptr [ebp - 0x218], ax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a3a                 | push                0x3a
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_4 = { 83c410 33c0 66399c24c8040000 740b 40 66399c44c8040000 }
            // n = 6, score = 200
            //   83c410               | add                 esp, 0x10
            //   33c0                 | xor                 eax, eax
            //   66399c24c8040000     | cmp                 word ptr [esp + 0x4c8], bx
            //   740b                 | je                  0xd
            //   40                   | inc                 eax
            //   66399c44c8040000     | cmp                 word ptr [esp + eax*2 + 0x4c8], bx

        $sequence_5 = { 68???????? 53 53 ffd6 83f87f 7c02 33c0 }
            // n = 7, score = 200
            //   68????????           |                     
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   83f87f               | cmp                 eax, 0x7f
            //   7c02                 | jl                  4
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 894608 85c0 7403 ff4604 5f 5e }
            // n = 6, score = 200
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   ff4604               | inc                 dword ptr [esi + 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { 8954242c 8b5708 89742420 8944241c 89742430 83c40c }
            // n = 6, score = 200
            //   8954242c             | mov                 dword ptr [esp + 0x2c], edx
            //   8b5708               | mov                 edx, dword ptr [edi + 8]
            //   89742420             | mov                 dword ptr [esp + 0x20], esi
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   89742430             | mov                 dword ptr [esp + 0x30], esi
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { e8???????? 8b5508 6a02 52 68???????? ba1f000000 8d75c0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   6a02                 | push                2
            //   52                   | push                edx
            //   68????????           |                     
            //   ba1f000000           | mov                 edx, 0x1f
            //   8d75c0               | lea                 esi, [ebp - 0x40]

        $sequence_9 = { 8b3d???????? c745f400000000 0f86c6000000 8b15???????? 33f6 8b45fc 8b440608 }
            // n = 7, score = 200
            //   8b3d????????         |                     
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   0f86c6000000         | jbe                 0xcc
            //   8b15????????         |                     
            //   33f6                 | xor                 esi, esi
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b440608             | mov                 eax, dword ptr [esi + eax + 8]

    condition:
        7 of them and filesize < 8626176
}