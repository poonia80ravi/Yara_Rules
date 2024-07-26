rule win_infy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.infy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.infy"
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
        $sequence_0 = { c705????????30104000 c705????????38104000 a3???????? 33c0 a3???????? 8915???????? }
            // n = 6, score = 200
            //   c705????????30104000     |     
            //   c705????????38104000     |     
            //   a3????????           |                     
            //   33c0                 | xor                 eax, eax
            //   a3????????           |                     
            //   8915????????         |                     

        $sequence_1 = { 85c0 7427 6a00 68???????? 68???????? 6a00 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   7427                 | je                  0x29
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_2 = { 5f 5e 5b c3 31c9 85d2 }
            // n = 6, score = 200
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   31c9                 | xor                 ecx, ecx
            //   85d2                 | test                edx, edx

        $sequence_3 = { 59 833b00 75f3 bb01000000 68???????? }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   833b00               | cmp                 dword ptr [ebx], 0
            //   75f3                 | jne                 0xfffffff5
            //   bb01000000           | mov                 ebx, 1
            //   68????????           |                     

        $sequence_4 = { 752c 57 e8???????? 3b461c 7521 }
            // n = 5, score = 200
            //   752c                 | jne                 0x2e
            //   57                   | push                edi
            //   e8????????           |                     
            //   3b461c               | cmp                 eax, dword ptr [esi + 0x1c]
            //   7521                 | jne                 0x23

        $sequence_5 = { 8d1401 895308 01f7 29cf }
            // n = 4, score = 200
            //   8d1401               | lea                 edx, [ecx + eax]
            //   895308               | mov                 dword ptr [ebx + 8], edx
            //   01f7                 | add                 edi, esi
            //   29cf                 | sub                 edi, ecx

        $sequence_6 = { 6a00 52 50 8b450c 50 51 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_7 = { 33ff 833d????????00 7417 8d45d0 50 }
            // n = 5, score = 200
            //   33ff                 | xor                 edi, edi
            //   833d????????00       |                     
            //   7417                 | je                  0x19
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax

        $sequence_8 = { 8d1492 83f901 83dfff c1e819 81e2ffffff01 09c1 83c830 }
            // n = 7, score = 200
            //   8d1492               | lea                 edx, [edx + edx*4]
            //   83f901               | cmp                 ecx, 1
            //   83dfff               | sbb                 edi, -1
            //   c1e819               | shr                 eax, 0x19
            //   81e2ffffff01         | and                 edx, 0x1ffffff
            //   09c1                 | or                  ecx, eax
            //   83c830               | or                  eax, 0x30

        $sequence_9 = { 0fb74af4 870c24 51 8b4afc e9???????? }
            // n = 5, score = 200
            //   0fb74af4             | movzx               ecx, word ptr [edx - 0xc]
            //   870c24               | xchg                dword ptr [esp], ecx
            //   51                   | push                ecx
            //   8b4afc               | mov                 ecx, dword ptr [edx - 4]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 147456
}