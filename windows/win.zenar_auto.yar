rule win_zenar_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.zenar."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zenar"
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
        $sequence_0 = { e8???????? 8b45ec 83f808 7235 8b4dd8 8d044502000000 8945d0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   83f808               | cmp                 eax, 8
            //   7235                 | jb                  0x37
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   8d044502000000       | lea                 eax, [eax*2 + 2]
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax

        $sequence_1 = { 8b0c8598ae4300 8b4514 c1e810 3244112d 2401 3044112d }
            // n = 6, score = 100
            //   8b0c8598ae4300       | mov                 ecx, dword ptr [eax*4 + 0x43ae98]
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   c1e810               | shr                 eax, 0x10
            //   3244112d             | xor                 al, byte ptr [ecx + edx + 0x2d]
            //   2401                 | and                 al, 1
            //   3044112d             | xor                 byte ptr [ecx + edx + 0x2d], al

        $sequence_2 = { 56 57 8b7d08 8d45d4 50 8b4fe4 e8???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   8b4fe4               | mov                 ecx, dword ptr [edi - 0x1c]
            //   e8????????           |                     

        $sequence_3 = { 8bec 8b4508 83781408 7202 8b00 50 ff15???????? }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83781408             | cmp                 dword ptr [eax + 0x14], 8
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 8910 894804 5d c20400 8b4118 c1e804 2401 }
            // n = 7, score = 100
            //   8910                 | mov                 dword ptr [eax], edx
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   8b4118               | mov                 eax, dword ptr [ecx + 0x18]
            //   c1e804               | shr                 eax, 4
            //   2401                 | and                 al, 1

        $sequence_5 = { 8945e0 8b03 8b4004 8b4c1838 8b411c 8b10 85d2 }
            // n = 7, score = 100
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   8b4c1838             | mov                 ecx, dword ptr [eax + ebx + 0x38]
            //   8b411c               | mov                 eax, dword ptr [ecx + 0x1c]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   85d2                 | test                edx, edx

        $sequence_6 = { 8365fc00 8b7d08 8bcf 8b5d0c 897db8 8365bc00 e8???????? }
            // n = 7, score = 100
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   897db8               | mov                 dword ptr [ebp - 0x48], edi
            //   8365bc00             | and                 dword ptr [ebp - 0x44], 0
            //   e8????????           |                     

        $sequence_7 = { ff75a8 e8???????? 59 59 84c0 }
            // n = 5, score = 100
            //   ff75a8               | push                dword ptr [ebp - 0x58]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   84c0                 | test                al, al

        $sequence_8 = { 43 85c0 781e 8b55ec 8d4aff 3bc1 7514 }
            // n = 7, score = 100
            //   43                   | inc                 ebx
            //   85c0                 | test                eax, eax
            //   781e                 | js                  0x20
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8d4aff               | lea                 ecx, [edx - 1]
            //   3bc1                 | cmp                 eax, ecx
            //   7514                 | jne                 0x16

        $sequence_9 = { 83f801 757c 0f1f4000 8b75e4 8b7de8 }
            // n = 5, score = 100
            //   83f801               | cmp                 eax, 1
            //   757c                 | jne                 0x7e
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8b75e4               | mov                 esi, dword ptr [ebp - 0x1c]
            //   8b7de8               | mov                 edi, dword ptr [ebp - 0x18]

    condition:
        7 of them and filesize < 519168
}