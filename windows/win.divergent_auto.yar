rule win_divergent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.divergent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.divergent"
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
        $sequence_0 = { 68???????? 68???????? 57 e8???????? 8d45fc 897dfc }
            // n = 6, score = 300
            //   68????????           |                     
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   897dfc               | mov                 dword ptr [ebp - 4], edi

        $sequence_1 = { e8???????? 50 e8???????? 8b4704 57 8d3498 e8???????? }
            // n = 7, score = 300
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   57                   | push                edi
            //   8d3498               | lea                 esi, [eax + ebx*4]
            //   e8????????           |                     

        $sequence_2 = { ff750c ff75fc ff15???????? ff75fc 85c0 0f4475f8 ff15???????? }
            // n = 7, score = 300
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax
            //   0f4475f8             | cmove               esi, dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_3 = { 8bf8 85ff 0f8400010000 53 56 }
            // n = 5, score = 300
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f8400010000         | je                  0x106
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_4 = { ff15???????? 837e0800 7412 ff7608 ff15???????? ff7608 e8???????? }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   837e0800             | cmp                 dword ptr [esi + 8], 0
            //   7412                 | je                  0x14
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff15????????         |                     
            //   ff7608               | push                dword ptr [esi + 8]
            //   e8????????           |                     

        $sequence_5 = { 50 ff7508 ff15???????? 83c414 8be5 5d c3 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_6 = { 6888130000 8bf8 ff15???????? ff15???????? 2bc7 b9a00f0000 3bc8 }
            // n = 7, score = 300
            //   6888130000           | push                0x1388
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   2bc7                 | sub                 eax, edi
            //   b9a00f0000           | mov                 ecx, 0xfa0
            //   3bc8                 | cmp                 ecx, eax

        $sequence_7 = { 68???????? 50 ff15???????? 85c0 6a01 58 0f44d8 }
            // n = 7, score = 300
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   6a01                 | push                1
            //   58                   | pop                 eax
            //   0f44d8               | cmove               ebx, eax

        $sequence_8 = { 59 85db 742c 53 }
            // n = 4, score = 300
            //   59                   | pop                 ecx
            //   85db                 | test                ebx, ebx
            //   742c                 | je                  0x2e
            //   53                   | push                ebx

        $sequence_9 = { 0fb6f1 0fb6ca 0fb60406 034510 03c8 81e1ff000080 7908 }
            // n = 7, score = 300
            //   0fb6f1               | movzx               esi, cl
            //   0fb6ca               | movzx               ecx, dl
            //   0fb60406             | movzx               eax, byte ptr [esi + eax]
            //   034510               | add                 eax, dword ptr [ebp + 0x10]
            //   03c8                 | add                 ecx, eax
            //   81e1ff000080         | and                 ecx, 0x800000ff
            //   7908                 | jns                 0xa

    condition:
        7 of them and filesize < 212992
}