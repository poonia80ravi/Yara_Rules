rule win_unidentified_095_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_095."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_095"
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
        $sequence_0 = { 4933fa 4b87bcfe90440200 33c0 488b5c2450 488b6c2458 488b742460 4883c420 }
            // n = 7, score = 100
            //   4933fa               | mov                 ecx, 4
            //   4b87bcfe90440200     | inc                 ebp
            //   33c0                 | xor                 eax, eax
            //   488b5c2450           | dec                 eax
            //   488b6c2458           | mov                 dword ptr [esp + 0x20], eax
            //   488b742460           | mov                 dword ptr [esp + 0x60], eax
            //   4883c420             | dec                 eax

        $sequence_1 = { 4885c0 751e 498bc6 4c8d3dfb9bffff 498784f7b8410200 4883c504 493bec }
            // n = 7, score = 100
            //   4885c0               | inc                 edx
            //   751e                 | or                  byte ptr [eax + esi*8 + 0x3d], 4
            //   498bc6               | cmp                 byte ptr [ebp - 0x71], dl
            //   4c8d3dfb9bffff       | jmp                 0x481
            //   498784f7b8410200     | mov                 dword ptr [ebp - 0x69], eax
            //   4883c504             | dec                 ebx
            //   493bec               | mov                 eax, dword ptr [edi + 0x245a0]

        $sequence_2 = { e8???????? 488bd8 4885c0 7475 488b542428 4c8bc0 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488bd8               | mov                 eax, dword ptr [ebx]
            //   4885c0               | dec                 eax
            //   7475                 | arpl                word ptr [eax], cx
            //   488b542428           | dec                 eax
            //   4c8bc0               | mov                 edx, ecx

        $sequence_3 = { ff15???????? 83f8ff 7411 a810 750d 33c9 bf01000000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83f8ff               | dec                 eax
            //   7411                 | mov                 dword ptr [esp + 0x840], eax
            //   a810                 | dec                 esp
            //   750d                 | mov                 dword ptr [esp + 0x20], ecx
            //   33c9                 | inc                 ebp
            //   bf01000000           | mov                 ecx, eax

        $sequence_4 = { 488d0df2dd0000 e8???????? 488d1516de0000 488d0d07de0000 e8???????? 488b4308 833800 }
            // n = 7, score = 100
            //   488d0df2dd0000       | jge                 0x56a
            //   e8????????           |                     
            //   488d1516de0000       | dec                 eax
            //   488d0d07de0000       | lea                 ecx, [0x1ea69]
            //   e8????????           |                     
            //   488b4308             | dec                 eax
            //   833800               | mov                 eax, dword ptr [edx + 8]

        $sequence_5 = { 0f8570010000 4c8d3d5b4effff 418bd3 4d8b8cc7a0450200 }
            // n = 4, score = 100
            //   0f8570010000         | dec                 eax
            //   4c8d3d5b4effff       | lea                 eax, [esp + 0x60]
            //   418bd3               | mov                 dword ptr [esp + 0x60], 4
            //   4d8b8cc7a0450200     | dec                 eax

        $sequence_6 = { 894c2428 488d156a4f0100 4889442420 e8???????? e9???????? 89758f e9???????? }
            // n = 7, score = 100
            //   894c2428             | mov                 ebp, dword ptr [esp + 0x58]
            //   488d156a4f0100       | sub                 ecx, eax
            //   4889442420           | je                  0x699
            //   e8????????           |                     
            //   e9????????           |                     
            //   89758f               | lea                 eax, [ecx - 1]
            //   e9????????           |                     

        $sequence_7 = { 7478 488d442468 c744246804000000 4889442428 4c8d4c2430 488d442460 4533c0 }
            // n = 7, score = 100
            //   7478                 | dec                 eax
            //   488d442468           | test                eax, eax
            //   c744246804000000     | je                  0x6a6
            //   4889442428           | dec                 eax
            //   4c8d4c2430           | mov                 ecx, ebx
            //   488d442460           | test                eax, eax
            //   4533c0               | jne                 0x6ab

        $sequence_8 = { 33ff 488d442450 48897c2440 488d542460 4889442438 }
            // n = 5, score = 100
            //   33ff                 | cmp                 dword ptr [esi + ecx*2], edi
            //   488d442450           | jne                 0x8a5
            //   48897c2440           | rep stosd           dword ptr es:[edi], eax
            //   488d542460           | dec                 eax
            //   4889442438           | lea                 edi, [0x148f8]

        $sequence_9 = { 7448 448d4304 498bd7 488bc8 ff15???????? 488bd8 4885c0 }
            // n = 7, score = 100
            //   7448                 | xor                 eax, esp
            //   448d4304             | dec                 eax
            //   498bd7               | mov                 dword ptr [esp + 0x830], eax
            //   488bc8               | test                eax, eax
            //   ff15????????         |                     
            //   488bd8               | je                  0x4da
            //   4885c0               | dec                 eax

    condition:
        7 of them and filesize < 339968
}