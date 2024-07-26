rule win_kardonloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.kardonloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kardonloader"
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
        $sequence_0 = { 5d c3 55 8bec 83ec68 0f2805???????? }
            // n = 6, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec68               | sub                 esp, 0x68
            //   0f2805????????       |                     

        $sequence_1 = { 85c0 0f840e020000 68???????? ff7508 e8???????? 59 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   0f840e020000         | je                  0x214
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_2 = { 53 56 e8???????? 83c40c 8bcf 5f }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8bcf                 | mov                 ecx, edi
            //   5f                   | pop                 edi

        $sequence_3 = { c3 55 8bec b888030100 e8???????? 56 }
            // n = 6, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b888030100           | mov                 eax, 0x10388
            //   e8????????           |                     
            //   56                   | push                esi

        $sequence_4 = { 50 ff7508 e8???????? 8b7dfc 8bd8 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8bd8                 | mov                 ebx, eax

        $sequence_5 = { ff15???????? be???????? 8d7dec 8d4dec 51 50 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   be????????           |                     
            //   8d7dec               | lea                 edi, [ebp - 0x14]
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_6 = { ff7508 e8???????? 59 59 85c0 0f840e020000 }
            // n = 6, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   0f840e020000         | je                  0x214

        $sequence_7 = { 50 6802020000 ff15???????? 85c0 740a b8???????? e9???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   b8????????           |                     
            //   e9????????           |                     

        $sequence_8 = { 83f8ff 7507 b8???????? eb1a 56 }
            // n = 5, score = 200
            //   83f8ff               | cmp                 eax, -1
            //   7507                 | jne                 9
            //   b8????????           |                     
            //   eb1a                 | jmp                 0x1c
            //   56                   | push                esi

        $sequence_9 = { 743c 8a10 84d2 57 7432 }
            // n = 5, score = 200
            //   743c                 | je                  0x3e
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   84d2                 | test                dl, dl
            //   57                   | push                edi
            //   7432                 | je                  0x34

    condition:
        7 of them and filesize < 57344
}