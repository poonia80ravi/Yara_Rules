rule win_pvzout_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pvzout."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pvzout"
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
        $sequence_0 = { 3e3f 19e9 73f8 dca10ebd24e8 252b0026cb }
            // n = 5, score = 200
            //   3e3f                 | aas                 
            //   19e9                 | sbb                 ecx, ebp
            //   73f8                 | jae                 0xfffffffa
            //   dca10ebd24e8         | fsub                qword ptr [ecx - 0x17db42f2]
            //   252b0026cb           | and                 eax, 0xcb26002b

        $sequence_1 = { 5a bf95f6810e 75a8 43 1dea50873a d4a1 }
            // n = 6, score = 200
            //   5a                   | pop                 edx
            //   bf95f6810e           | mov                 edi, 0xe81f695
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   1dea50873a           | sbb                 eax, 0x3a8750ea
            //   d4a1                 | aam                 0xa1

        $sequence_2 = { 9c b3d7 5a bf95f6810e 75a8 }
            // n = 5, score = 200
            //   9c                   | pushfd              
            //   b3d7                 | mov                 bl, 0xd7
            //   5a                   | pop                 edx
            //   bf95f6810e           | mov                 edi, 0xe81f695
            //   75a8                 | jne                 0xffffffaa

        $sequence_3 = { bbedffffff 03dd 81eb00d00200 83bd8804000000 899d88040000 }
            // n = 5, score = 200
            //   bbedffffff           | mov                 ebx, 0xffffffed
            //   03dd                 | add                 ebx, ebp
            //   81eb00d00200         | sub                 ebx, 0x2d000
            //   83bd8804000000       | cmp                 dword ptr [ebp + 0x488], 0
            //   899d88040000         | mov                 dword ptr [ebp + 0x488], ebx

        $sequence_4 = { 3089f33d80f3 48 e21c 3e3f }
            // n = 4, score = 200
            //   3089f33d80f3         | xor                 byte ptr [ecx - 0xc7fc20d], cl
            //   48                   | dec                 eax
            //   e21c                 | loop                0x1e
            //   3e3f                 | aas                 

        $sequence_5 = { 5d bbedffffff 03dd 81eb00d00200 83bd8804000000 }
            // n = 5, score = 200
            //   5d                   | pop                 ebp
            //   bbedffffff           | mov                 ebx, 0xffffffed
            //   03dd                 | add                 ebx, ebp
            //   81eb00d00200         | sub                 ebx, 0x2d000
            //   83bd8804000000       | cmp                 dword ptr [ebp + 0x488], 0

        $sequence_6 = { 03dd 81eb00d00200 83bd8804000000 899d88040000 }
            // n = 4, score = 200
            //   03dd                 | add                 ebx, ebp
            //   81eb00d00200         | sub                 ebx, 0x2d000
            //   83bd8804000000       | cmp                 dword ptr [ebp + 0x488], 0
            //   899d88040000         | mov                 dword ptr [ebp + 0x488], ebx

        $sequence_7 = { d4a1 0e 75a8 43 }
            // n = 4, score = 200
            //   d4a1                 | aam                 0xa1
            //   0e                   | push                cs
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx

        $sequence_8 = { 81eb00d00200 83bd8804000000 899d88040000 0f85cb030000 8d8594040000 50 }
            // n = 6, score = 200
            //   81eb00d00200         | sub                 ebx, 0x2d000
            //   83bd8804000000       | cmp                 dword ptr [ebp + 0x488], 0
            //   899d88040000         | mov                 dword ptr [ebp + 0x488], ebx
            //   0f85cb030000         | jne                 0x3d1
            //   8d8594040000         | lea                 eax, [ebp + 0x494]
            //   50                   | push                eax

        $sequence_9 = { 5a bf95f6810e 75a8 43 1dea50873a d4a1 0e }
            // n = 7, score = 200
            //   5a                   | pop                 edx
            //   bf95f6810e           | mov                 edi, 0xe81f695
            //   75a8                 | jne                 0xffffffaa
            //   43                   | inc                 ebx
            //   1dea50873a           | sbb                 eax, 0x3a8750ea
            //   d4a1                 | aam                 0xa1
            //   0e                   | push                cs

    condition:
        7 of them and filesize < 573440
}