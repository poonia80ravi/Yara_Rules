rule win_bleachgap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bleachgap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bleachgap"
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
        $sequence_0 = { ff35???????? 53 e8???????? 8bf8 83c40c 85ff 753e }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c40c               | add                 esp, 0xc
            //   85ff                 | test                edi, edi
            //   753e                 | jne                 0x40

        $sequence_1 = { c68505feffff56 c68506feffff4b c68507feffff49 c68508feffff04 c68509feffff14 c6850afeffff0a c6850bfeffff14 }
            // n = 7, score = 100
            //   c68505feffff56       | mov                 byte ptr [ebp - 0x1fb], 0x56
            //   c68506feffff4b       | mov                 byte ptr [ebp - 0x1fa], 0x4b
            //   c68507feffff49       | mov                 byte ptr [ebp - 0x1f9], 0x49
            //   c68508feffff04       | mov                 byte ptr [ebp - 0x1f8], 4
            //   c68509feffff14       | mov                 byte ptr [ebp - 0x1f7], 0x14
            //   c6850afeffff0a       | mov                 byte ptr [ebp - 0x1f6], 0xa
            //   c6850bfeffff14       | mov                 byte ptr [ebp - 0x1f5], 0x14

        $sequence_2 = { e8???????? 8be8 83c410 83fdff 0f841b010000 55 53 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8be8                 | mov                 ebp, eax
            //   83c410               | add                 esp, 0x10
            //   83fdff               | cmp                 ebp, -1
            //   0f841b010000         | je                  0x121
            //   55                   | push                ebp
            //   53                   | push                ebx

        $sequence_3 = { 8b442460 8bf8 899c2480000000 03bc24b4000000 135c2464 33ef 33cb }
            // n = 7, score = 100
            //   8b442460             | mov                 eax, dword ptr [esp + 0x60]
            //   8bf8                 | mov                 edi, eax
            //   899c2480000000       | mov                 dword ptr [esp + 0x80], ebx
            //   03bc24b4000000       | add                 edi, dword ptr [esp + 0xb4]
            //   135c2464             | adc                 ebx, dword ptr [esp + 0x64]
            //   33ef                 | xor                 ebp, edi
            //   33cb                 | xor                 ecx, ebx

        $sequence_4 = { eb25 8b542420 8b6c2414 8b44243c 8944242c 8d0c12 894c2418 }
            // n = 7, score = 100
            //   eb25                 | jmp                 0x27
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   8b6c2414             | mov                 ebp, dword ptr [esp + 0x14]
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]
            //   8944242c             | mov                 dword ptr [esp + 0x2c], eax
            //   8d0c12               | lea                 ecx, [edx + edx]
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx

        $sequence_5 = { 8b37 85f6 7511 e8???????? 8bf0 85f6 0f841f020000 }
            // n = 7, score = 100
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   85f6                 | test                esi, esi
            //   7511                 | jne                 0x13
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f841f020000         | je                  0x225

        $sequence_6 = { ff742418 ff742428 ff742428 e8???????? 83c410 85c0 0f8470020000 }
            // n = 7, score = 100
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   ff742428             | push                dword ptr [esp + 0x28]
            //   ff742428             | push                dword ptr [esp + 0x28]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   0f8470020000         | je                  0x276

        $sequence_7 = { c744241400000000 85c9 744e ffb02c010000 8d442428 50 56 }
            // n = 7, score = 100
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   85c9                 | test                ecx, ecx
            //   744e                 | je                  0x50
            //   ffb02c010000         | push                dword ptr [eax + 0x12c]
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_8 = { eb12 8b442414 40 33ed 89442414 eb05 bd01000000 }
            // n = 7, score = 100
            //   eb12                 | jmp                 0x14
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   40                   | inc                 eax
            //   33ed                 | xor                 ebp, ebp
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   eb05                 | jmp                 7
            //   bd01000000           | mov                 ebp, 1

        $sequence_9 = { 8a0c01 3208 880a 8b4c2444 03c8 8818 3bcf }
            // n = 7, score = 100
            //   8a0c01               | mov                 cl, byte ptr [ecx + eax]
            //   3208                 | xor                 cl, byte ptr [eax]
            //   880a                 | mov                 byte ptr [edx], cl
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   03c8                 | add                 ecx, eax
            //   8818                 | mov                 byte ptr [eax], bl
            //   3bcf                 | cmp                 ecx, edi

    condition:
        7 of them and filesize < 4538368
}