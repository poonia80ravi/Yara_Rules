rule win_krbanker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.krbanker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krbanker"
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
        $sequence_0 = { 8d0440 8b548414 85d2 7501 49 }
            // n = 5, score = 400
            //   8d0440               | lea                 eax, [eax + eax*2]
            //   8b548414             | mov                 edx, dword ptr [esp + eax*4 + 0x14]
            //   85d2                 | test                edx, edx
            //   7501                 | jne                 3
            //   49                   | dec                 ecx

        $sequence_1 = { 8b4d08 5f 5e 8b11 895500 8b4104 894504 }
            // n = 7, score = 400
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   895500               | mov                 dword ptr [ebp], edx
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   894504               | mov                 dword ptr [ebp + 4], eax

        $sequence_2 = { 83c408 c3 8b7114 33d2 }
            // n = 4, score = 400
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   8b7114               | mov                 esi, dword ptr [ecx + 0x14]
            //   33d2                 | xor                 edx, edx

        $sequence_3 = { 6a00 6870000000 6801000000 bb40010000 e8???????? 83c410 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   6870000000           | push                0x70
            //   6801000000           | push                1
            //   bb40010000           | mov                 ebx, 0x140
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_4 = { 50 8b5d08 8b1b 53 8b0b }
            // n = 5, score = 400
            //   50                   | push                eax
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   53                   | push                ebx
            //   8b0b                 | mov                 ecx, dword ptr [ebx]

        $sequence_5 = { 6a00 684b000000 6801000000 bb40010000 e8???????? }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   684b000000           | push                0x4b
            //   6801000000           | push                1
            //   bb40010000           | mov                 ebx, 0x140
            //   e8????????           |                     

        $sequence_6 = { 6801000000 e8???????? 83c404 c1e002 03d8 895dc8 8b5dfc }
            // n = 7, score = 400
            //   6801000000           | push                1
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c1e002               | shl                 eax, 2
            //   03d8                 | add                 ebx, eax
            //   895dc8               | mov                 dword ptr [ebp - 0x38], ebx
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]

        $sequence_7 = { c745fc00000000 c745f800000000 c745f400000000 c745f000000000 6805000080 }
            // n = 5, score = 400
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   6805000080           | push                0x80000005

        $sequence_8 = { 8b5df8 8903 8965f8 6810000000 8b45fc 50 6810000000 }
            // n = 7, score = 400
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   8903                 | mov                 dword ptr [ebx], eax
            //   8965f8               | mov                 dword ptr [ebp - 8], esp
            //   6810000000           | push                0x10
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   6810000000           | push                0x10

        $sequence_9 = { 7431 85f6 75e3 84c0 }
            // n = 4, score = 400
            //   7431                 | je                  0x33
            //   85f6                 | test                esi, esi
            //   75e3                 | jne                 0xffffffe5
            //   84c0                 | test                al, al

    condition:
        7 of them and filesize < 1826816
}