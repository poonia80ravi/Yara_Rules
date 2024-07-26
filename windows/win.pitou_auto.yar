rule win_pitou_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pitou."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pitou"
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
        $sequence_0 = { 8a6201 80f457 8acc 80e103 8aec c0ed03 }
            // n = 6, score = 700
            //   8a6201               | dec                 esp
            //   80f457               | aaa                 
            //   8acc                 | sbb                 al, 0x70
            //   80e103               | popfd               
            //   8aec                 | pop                 es
            //   c0ed03               | jge                 0xdd7

        $sequence_1 = { ac 8bda c1e305 03c3 8bda }
            // n = 5, score = 700
            //   ac                   | cmp                 edx, eax
            //   8bda                 | jne                 0x130a0
            //   c1e305               | mov                 al, 1
            //   03c3                 | mov                 edx, eax
            //   8bda                 | and                 edx, ecx

        $sequence_2 = { 8acc 80e103 8aec c0ed03 80e507 }
            // n = 5, score = 700
            //   8acc                 | mov                 dword ptr [ebp - 4], eax
            //   80e103               | cmp                 dword ptr [ebp - 4], 0x93
            //   8aec                 | jae                 0x956
            //   c0ed03               | mov                 ecx, dword ptr [ebp - 4]
            //   80e507               | add                 eax, 1

        $sequence_3 = { 8bda c1e305 03c3 8bda c1eb02 }
            // n = 5, score = 700
            //   8bda                 | dec                 esp
            //   c1e305               | imul                ebp, eax
            //   03c3                 | inc                 esp
            //   8bda                 | mov                 dword ptr [ebx], ebp
            //   c1eb02               | dec                 eax

        $sequence_4 = { c1e305 03c3 8bda c1eb02 }
            // n = 4, score = 700
            //   c1e305               | adc                 bl, byte ptr [edx + 0x242eab53]
            //   03c3                 | xor                 al, 0x39
            //   8bda                 | xchg                eax, edx
            //   c1eb02               | imul                eax, dword ptr [esi], 0x94169a03

        $sequence_5 = { 8afb 80e703 c0eb05 80e303 }
            // n = 4, score = 700
            //   8afb                 | push                1
            //   80e703               | test                eax, eax
            //   c0eb05               | jne                 0x1c3c
            //   80e303               | push                0x10

        $sequence_6 = { 80e103 8aec c0ed03 80e507 }
            // n = 4, score = 700
            //   80e103               | mov                 dword ptr fs:[0], esp
            //   8aec                 | sub                 esp, 0x820
            //   c0ed03               | push                ebx
            //   80e507               | push                esi

        $sequence_7 = { 80f457 8acc 80e103 8aec c0ed03 }
            // n = 5, score = 700
            //   80f457               | je                  0x10c98
            //   8acc                 | mov                 ecx, dword ptr [esi + 8]
            //   80e103               | push                esi
            //   8aec                 | mov                 esi, dword ptr [ebp + 0x10]
            //   c0ed03               | test                esi, esi

        $sequence_8 = { 33c0 ac 8bda c1e305 03c3 8bda c1eb02 }
            // n = 7, score = 700
            //   33c0                 | movzx               eax, word ptr [edi + 0x10]
            //   ac                   | setne               cl
            //   8bda                 | add                 ecx, eax
            //   c1e305               | test                ecx, ecx
            //   03c3                 | jle                 0xffffe464
            //   8bda                 | dec                 esp
            //   c1eb02               | mov                 dword ptr [ebx], ebp

        $sequence_9 = { 8bda c1eb02 03c3 33d0 }
            // n = 4, score = 700
            //   8bda                 | mov                 ecx, dword ptr [eax + 0xc]
            //   c1eb02               | add                 ecx, 0xbffefffc
            //   03c3                 | cmp                 ecx, 0x1f
            //   33d0                 | mov                 eax, dword ptr [ebp + 0x10]

    condition:
        7 of them and filesize < 1106944
}