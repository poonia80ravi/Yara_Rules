rule win_outlook_backdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.outlook_backdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.outlook_backdoor"
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
        $sequence_0 = { 8d4de0 e8???????? 83c420 8d45e0 50 8d4dc4 e8???????? }
            // n = 7, score = 600
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]
            //   e8????????           |                     

        $sequence_1 = { ff15???????? 85c0 7505 e8???????? 57 ff15???????? ff75f0 }
            // n = 7, score = 600
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_2 = { ff36 ffd3 6a01 6a00 ff75fc ff36 ffd7 }
            // n = 7, score = 600
            //   ff36                 | push                dword ptr [esi]
            //   ffd3                 | call                ebx
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff36                 | push                dword ptr [esi]
            //   ffd7                 | call                edi

        $sequence_3 = { 53 50 ff5150 8bf0 e8???????? ff750c 8b470c }
            // n = 7, score = 600
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff5150               | call                dword ptr [ecx + 0x50]
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]

        $sequence_4 = { 6a01 8d75b4 e8???????? 57 6a01 8d75d0 }
            // n = 6, score = 600
            //   6a01                 | push                1
            //   8d75b4               | lea                 esi, [ebp - 0x4c]
            //   e8????????           |                     
            //   57                   | push                edi
            //   6a01                 | push                1
            //   8d75d0               | lea                 esi, [ebp - 0x30]

        $sequence_5 = { 895104 e8???????? ff4e08 59 8b442404 8907 8bc7 }
            // n = 7, score = 600
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   e8????????           |                     
            //   ff4e08               | dec                 dword ptr [esi + 8]
            //   59                   | pop                 ecx
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8907                 | mov                 dword ptr [edi], eax
            //   8bc7                 | mov                 eax, edi

        $sequence_6 = { 51 ff10 8b03 8b4004 03c3 c6403030 8d45d0 }
            // n = 7, score = 600
            //   51                   | push                ecx
            //   ff10                 | call                dword ptr [eax]
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   03c3                 | add                 eax, ebx
            //   c6403030             | mov                 byte ptr [eax + 0x30], 0x30
            //   8d45d0               | lea                 eax, [ebp - 0x30]

        $sequence_7 = { eb03 8d5104 8b4914 8d0c4a 894804 c700fcffffff c3 }
            // n = 7, score = 600
            //   eb03                 | jmp                 5
            //   8d5104               | lea                 edx, [ecx + 4]
            //   8b4914               | mov                 ecx, dword ptr [ecx + 0x14]
            //   8d0c4a               | lea                 ecx, [edx + ecx*2]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   c700fcffffff         | mov                 dword ptr [eax], 0xfffffffc
            //   c3                   | ret                 

        $sequence_8 = { 8b4c2414 2b4c2410 53 53 51 ff74241c 50 }
            // n = 7, score = 600
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   2b4c2410             | sub                 ecx, dword ptr [esp + 0x10]
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   50                   | push                eax

        $sequence_9 = { 7413 ff7608 8bc1 e8???????? ff7604 e8???????? 59 }
            // n = 7, score = 600
            //   7413                 | je                  0x15
            //   ff7608               | push                dword ptr [esi + 8]
            //   8bc1                 | mov                 eax, ecx
            //   e8????????           |                     
            //   ff7604               | push                dword ptr [esi + 4]
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 2912256
}