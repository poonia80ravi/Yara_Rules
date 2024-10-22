rule win_darkside_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.darkside."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkside"
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
        $sequence_0 = { fec1 75da eb06 33db }
            // n = 4, score = 1100
            //   fec1                 | inc                 cl
            //   75da                 | jne                 0xffffffdc
            //   eb06                 | jmp                 8
            //   33db                 | xor                 ebx, ebx

        $sequence_1 = { 56 57 8b7d08 8b450c b9ff000000 }
            // n = 5, score = 1100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   b9ff000000           | mov                 ecx, 0xff

        $sequence_2 = { 5b 5d c20800 55 8bec 53 51 }
            // n = 7, score = 1100
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   51                   | push                ecx

        $sequence_3 = { b9ff000000 33d2 f7f1 85c0 }
            // n = 4, score = 1100
            //   b9ff000000           | mov                 ecx, 0xff
            //   33d2                 | xor                 edx, edx
            //   f7f1                 | div                 ecx
            //   85c0                 | test                eax, eax

        $sequence_4 = { 8b7808 8b400c 89540e0c 89440e08 }
            // n = 4, score = 1100
            //   8b7808               | mov                 edi, dword ptr [eax + 8]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   89540e0c             | mov                 dword ptr [esi + ecx + 0xc], edx
            //   89440e08             | mov                 dword ptr [esi + ecx + 8], eax

        $sequence_5 = { e8???????? 81c7ff000000 4b 85db 75ea 85d2 }
            // n = 6, score = 1100
            //   e8????????           |                     
            //   81c7ff000000         | add                 edi, 0xff
            //   4b                   | dec                 ebx
            //   85db                 | test                ebx, ebx
            //   75ea                 | jne                 0xffffffec
            //   85d2                 | test                edx, edx

        $sequence_6 = { 8b4508 8b10 8b5804 8b7808 8b400c }
            // n = 5, score = 1100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8b5804               | mov                 ebx, dword ptr [eax + 4]
            //   8b7808               | mov                 edi, dword ptr [eax + 8]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]

        $sequence_7 = { 52 56 57 b9f0000000 be???????? 8b4508 8b10 }
            // n = 7, score = 1100
            //   52                   | push                edx
            //   56                   | push                esi
            //   57                   | push                edi
            //   b9f0000000           | mov                 ecx, 0xf0
            //   be????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_8 = { 89540e0c 89440e08 895c0e04 893c0e }
            // n = 4, score = 1100
            //   89540e0c             | mov                 dword ptr [esi + ecx + 0xc], edx
            //   89440e08             | mov                 dword ptr [esi + ecx + 8], eax
            //   895c0e04             | mov                 dword ptr [esi + ecx + 4], ebx
            //   893c0e               | mov                 dword ptr [esi + ecx], edi

        $sequence_9 = { 81ea10101010 2d10101010 81eb10101010 81ef10101010 }
            // n = 4, score = 1100
            //   81ea10101010         | sub                 edx, 0x10101010
            //   2d10101010           | sub                 eax, 0x10101010
            //   81eb10101010         | sub                 ebx, 0x10101010
            //   81ef10101010         | sub                 edi, 0x10101010

    condition:
        7 of them and filesize < 286720
}