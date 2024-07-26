rule win_headertip_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.headertip."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.headertip"
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
        $sequence_0 = { 897df4 ff15???????? 814dfc00010000 57 8d45fc 50 }
            // n = 6, score = 100
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   ff15????????         |                     
            //   814dfc00010000       | or                  dword ptr [ebp - 4], 0x100
            //   57                   | push                edi
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax

        $sequence_1 = { 74c4 ff4c2414 57 ff33 e8???????? 03c7 68???????? }
            // n = 7, score = 100
            //   74c4                 | je                  0xffffffc6
            //   ff4c2414             | dec                 dword ptr [esp + 0x14]
            //   57                   | push                edi
            //   ff33                 | push                dword ptr [ebx]
            //   e8????????           |                     
            //   03c7                 | add                 eax, edi
            //   68????????           |                     

        $sequence_2 = { c6452f66 c645306f c6453157 885d32 c6459c49 c6459d6e }
            // n = 6, score = 100
            //   c6452f66             | mov                 byte ptr [ebp + 0x2f], 0x66
            //   c645306f             | mov                 byte ptr [ebp + 0x30], 0x6f
            //   c6453157             | mov                 byte ptr [ebp + 0x31], 0x57
            //   885d32               | mov                 byte ptr [ebp + 0x32], bl
            //   c6459c49             | mov                 byte ptr [ebp - 0x64], 0x49
            //   c6459d6e             | mov                 byte ptr [ebp - 0x63], 0x6e

        $sequence_3 = { e8???????? 59 59 85c0 740a 0375fc }
            // n = 6, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   0375fc               | add                 esi, dword ptr [ebp - 4]

        $sequence_4 = { 0f852bfeffff 8d4568 50 ff15???????? a3???????? 3bc3 0f848e000000 }
            // n = 7, score = 100
            //   0f852bfeffff         | jne                 0xfffffe31
            //   8d4568               | lea                 eax, [ebp + 0x68]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     
            //   3bc3                 | cmp                 eax, ebx
            //   0f848e000000         | je                  0x94

        $sequence_5 = { 0fb74818 ba0b010000 663bca 740c b80b020000 }
            // n = 5, score = 100
            //   0fb74818             | movzx               ecx, word ptr [eax + 0x18]
            //   ba0b010000           | mov                 edx, 0x10b
            //   663bca               | cmp                 cx, dx
            //   740c                 | je                  0xe
            //   b80b020000           | mov                 eax, 0x20b

        $sequence_6 = { 7434 8b07 ff4d08 03c3 56 50 e8???????? }
            // n = 7, score = 100
            //   7434                 | je                  0x36
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   03c3                 | add                 eax, ebx
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { 68???????? be???????? 56 c705????????19100010 c705????????5b120010 ff15???????? }
            // n = 6, score = 100
            //   68????????           |                     
            //   be????????           |                     
            //   56                   | push                esi
            //   c705????????19100010     |     
            //   c705????????5b120010     |     
            //   ff15????????         |                     

        $sequence_8 = { 83e806 7419 48 740a 51 51 }
            // n = 6, score = 100
            //   83e806               | sub                 eax, 6
            //   7419                 | je                  0x1b
            //   48                   | dec                 eax
            //   740a                 | je                  0xc
            //   51                   | push                ecx
            //   51                   | push                ecx

        $sequence_9 = { 50 ff35???????? c6454456 c6454569 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   ff35????????         |                     
            //   c6454456             | mov                 byte ptr [ebp + 0x44], 0x56
            //   c6454569             | mov                 byte ptr [ebp + 0x45], 0x69

    condition:
        7 of them and filesize < 174080
}