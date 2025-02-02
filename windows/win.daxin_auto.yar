rule win_daxin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.daxin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.daxin"
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
        $sequence_0 = { 2bc2 d1f8 99 f7f9 }
            // n = 4, score = 400
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_1 = { 4c8bce be02000000 41b800000010 8bd6 }
            // n = 4, score = 300
            //   4c8bce               | movzx               eax, ax
            //   be02000000           | inc                 ecx
            //   41b800000010         | shr                 ecx, 8
            //   8bd6                 | dec                 esp

        $sequence_2 = { 4c8bcf 48896c2428 21542420 ff15???????? }
            // n = 4, score = 300
            //   4c8bcf               | inc                 esp
            //   48896c2428           | mov                 byte ptr [edx + 0x4b], al
            //   21542420             | dec                 esp
            //   ff15????????         |                     

        $sequence_3 = { 4c8bca 4488424b 4c2bc8 44899ad0000000 }
            // n = 4, score = 300
            //   4c8bca               | dec                 esp
            //   4488424b             | mov                 eax, edi
            //   4c2bc8               | mov                 edx, 0xc
            //   44899ad0000000       | inc                 esp

        $sequence_4 = { d3e0 0bf0 0fb703 4883c302 }
            // n = 4, score = 300
            //   d3e0                 | shl                 eax, cl
            //   0bf0                 | or                  esi, eax
            //   0fb703               | movzx               eax, word ptr [ebx]
            //   4883c302             | dec                 eax

        $sequence_5 = { 4c8bc7 ba0c000000 448bc8 66c1e008 }
            // n = 4, score = 300
            //   4c8bc7               | lea                 ecx, [esp + eax]
            //   ba0c000000           | dec                 eax
            //   448bc8               | mov                 edx, ebp
            //   66c1e008             | dec                 esp

        $sequence_6 = { 4c8bc9 e8???????? 498bd0 498bc9 }
            // n = 4, score = 300
            //   4c8bc9               | inc                 esp
            //   e8????????           |                     
            //   498bd0               | mov                 ecx, eax
            //   498bc9               | shl                 ax, 8

        $sequence_7 = { 4c8bc7 498d0c04 488bd5 e8???????? }
            // n = 4, score = 300
            //   4c8bc7               | add                 ebx, 2
            //   498d0c04             | dec                 esp
            //   488bd5               | mov                 eax, edi
            //   e8????????           |                     

        $sequence_8 = { 884704 898e88000000 c7868c00000000000000 899690000000 }
            // n = 4, score = 100
            //   884704               | dec                 eax
            //   898e88000000         | lea                 eax, [esp + 0x98]
            //   c7868c00000000000000     | inc    esp
            //   899690000000         | lea                 eax, [ebx + 2]

        $sequence_9 = { 884704 8b4640 85c0 7416 }
            // n = 4, score = 100
            //   884704               | mov                 byte ptr [esi + 9], dl
            //   8b4640               | mov                 eax, dword ptr [edi + 0x28]
            //   85c0                 | mov                 byte ptr [esi + 6], al
            //   7416                 | mov                 byte ptr [esi + 8], 0x80

        $sequence_10 = { 884704 8b0e 8bc6 85c9 }
            // n = 4, score = 100
            //   884704               | xor                 edx, edx
            //   8b0e                 | sub                 eax, edi
            //   8bc6                 | mov                 byte ptr [esi + 4], al
            //   85c9                 | mov                 eax, edi

        $sequence_11 = { 884606 c6460880 8a5730 885609 }
            // n = 4, score = 100
            //   884606               | and                 dword ptr [esp + 0x20], edx
            //   c6460880             | dec                 esp
            //   8a5730               | mov                 ecx, edi
            //   885609               | dec                 eax

        $sequence_12 = { 884704 8b4648 85c0 c7868000000000000000 }
            // n = 4, score = 100
            //   884704               | jle                 0x38
            //   8b4648               | mov                 ecx, dword ptr [esp + 0x14]
            //   85c0                 | mov                 byte ptr [edi + 4], al
            //   c7868000000000000000     | xor    eax, eax

        $sequence_13 = { 884704 33c0 85ed 7e32 }
            // n = 4, score = 100
            //   884704               | dec                 esp
            //   33c0                 | mov                 ebx, eax
            //   85ed                 | dec                 eax
            //   7e32                 | test                eax, eax

        $sequence_14 = { 884604 8bc7 8b7e14 33d2 }
            // n = 4, score = 100
            //   884604               | mov                 edx, esi
            //   8bc7                 | dec                 esp
            //   8b7e14               | mov                 ecx, esi
            //   33d2                 | mov                 esi, 2

    condition:
        7 of them and filesize < 3475456
}