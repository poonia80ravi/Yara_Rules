rule win_skip20_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.skip20."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.skip20"
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
        $sequence_0 = { 8b0d???????? ba01000000 c705????????01000000 ff15???????? 8bc3 488b8c2460200000 4833cc }
            // n = 7, score = 200
            //   8b0d????????         |                     
            //   ba01000000           | push                esp
            //   c705????????01000000     |     
            //   ff15????????         |                     
            //   8bc3                 | inc                 ecx
            //   488b8c2460200000     | push                ebp
            //   4833cc               | mov                 eax, 0x4218

        $sequence_1 = { 488d150f2e0100 e9???????? 4c896c2450 c7842490000000204963d8 }
            // n = 4, score = 200
            //   488d150f2e0100       | dec                 ecx
            //   e9????????           |                     
            //   4c896c2450           | add                 ebx, ebp
            //   c7842490000000204963d8     | dec    eax

        $sequence_2 = { 898424c0000000 418d46ec 488be9 4c8d2dd89fffff 83f848 0f87bf010000 }
            // n = 6, score = 200
            //   898424c0000000       | mov                 ecx, 0x1b
            //   418d46ec             | dec                 esp
            //   488be9               | lea                 eax, [esp + 0x190]
            //   4c8d2dd89fffff       | mov                 edx, edi
            //   83f848               | dec                 eax
            //   0f87bf010000         | mov                 ecx, ebx

        $sequence_3 = { 498980a0000000 66394a18 7557 4923c5 498d4834 498980a0000000 e8???????? }
            // n = 7, score = 200
            //   498980a0000000       | mov                 ecx, dword ptr [esp + 0x98]
            //   66394a18             | mov                 eax, dword ptr [ebx + 4]
            //   7557                 | inc                 ecx
            //   4923c5               | test                dl, 1
            //   498d4834             | mov                 eax, 1
            //   498980a0000000       | test                ebx, ebx
            //   e8????????           |                     

        $sequence_4 = { e8???????? 440fb74c2472 440fb7442470 85c0 7447 0fb7c3 0fb754247c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   440fb74c2472         | ja                  0xa4c
            //   440fb7442470         | add                 ecx, 0x3c
            //   85c0                 | mov                 ecx, dword ptr [esp + 0x98]
            //   7447                 | inc                 edx
            //   0fb7c3               | lea                 ecx, [ecx + ebx*8]
            //   0fb754247c           | mov                 eax, 0x40

        $sequence_5 = { 0f87d3fdffff 4c8d15959cffff 4898 410fb68402c0720000 418b8c82f0710000 4903ca ffe1 }
            // n = 7, score = 200
            //   0f87d3fdffff         | mov                 ecx, dword ptr [ecx + eax*8]
            //   4c8d15959cffff       | inc                 esp
            //   4898                 | mov                 dword ptr [esp + 0x44], edi
            //   410fb68402c0720000     | dec    esp
            //   418b8c82f0710000     | mov                 edi, dword ptr [esp + 0x60]
            //   4903ca               | dec                 ecx
            //   ffe1                 | mov                 ecx, dword ptr [edi + ecx]

        $sequence_6 = { 4883c308 483bdf 72ed 48833d????????00 741f 488d0d02410500 e8???????? }
            // n = 7, score = 200
            //   4883c308             | sub                 ecx, dword ptr [ebp]
            //   483bdf               | add                 ecx, ebx
            //   72ed                 | jbe                 0x3bb
            //   48833d????????00     |                     
            //   741f                 | dec                 eax
            //   488d0d02410500       | lea                 esi, [esp + 0xec]
            //   e8????????           |                     

        $sequence_7 = { 741f 488d0d02410500 e8???????? 85c0 740f 4533c0 33c9 }
            // n = 7, score = 200
            //   741f                 | cmp                 eax, 0x800
            //   488d0d02410500       | je                  0xbce
            //   e8????????           |                     
            //   85c0                 | cmp                 eax, 0x1000
            //   740f                 | jmp                 0xbe8
            //   4533c0               | inc                 ecx
            //   33c9                 | or                  dword ptr [eax], 0x4000

        $sequence_8 = { ffca 744f ffca 0f8500030000 410fbae118 7319 410fbae119 }
            // n = 7, score = 200
            //   ffca                 | jne                 0x1189
            //   744f                 | bt                  esi, 0x10
            //   ffca                 | jae                 0x1118
            //   0f8500030000         | test                esi, 0x1000008
            //   410fbae118           | jne                 0x1118
            //   7319                 | or                  dword ptr [edi + 4], 0x2000
            //   410fbae119           | inc                 ebp

        $sequence_9 = { 448d4e02 448d4632 33c9 c744242864000000 89742440 4889442420 e8???????? }
            // n = 7, score = 200
            //   448d4e02             | or                  dword ptr [esi + 4], 0x2000000
            //   448d4632             | add                 edx, 8
            //   33c9                 | mov                 word ptr [ebx + edi*4 + 0x24], ax
            //   c744242864000000     | inc                 ecx
            //   89742440             | test                bl, 4
            //   4889442420           | je                  0x18c1
            //   e8????????           |                     

    condition:
        7 of them and filesize < 794624
}