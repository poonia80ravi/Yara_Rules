rule win_bredolab_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bredolab."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bredolab"
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
        $sequence_0 = { 8a08 84c9 8b55a4 740d 8d7600 }
            // n = 5, score = 200
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   84c9                 | test                cl, cl
            //   8b55a4               | mov                 edx, dword ptr [ebp - 0x5c]
            //   740d                 | je                  0xf
            //   8d7600               | lea                 esi, [esi]

        $sequence_1 = { e8???????? e9???????? 89f3 c7864c09000000000000 40 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   e9????????           |                     
            //   89f3                 | mov                 ebx, esi
            //   c7864c09000000000000     | mov    dword ptr [esi + 0x94c], 0
            //   40                   | inc                 eax

        $sequence_2 = { e8???????? 8d8530ffffff 89442404 c7042402000000 e8???????? 8d8520ffffff 89442404 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8d8530ffffff         | lea                 eax, [ebp - 0xd0]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c7042402000000       | mov                 dword ptr [esp], 2
            //   e8????????           |                     
            //   8d8520ffffff         | lea                 eax, [ebp - 0xe0]
            //   89442404             | mov                 dword ptr [esp + 4], eax

        $sequence_3 = { e8???????? 84c0 7407 807c3da800 7412 83c308 8b03 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7407                 | je                  9
            //   807c3da800           | cmp                 byte ptr [ebp + edi - 0x58], 0
            //   7412                 | je                  0x14
            //   83c308               | add                 ebx, 8
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_4 = { 31d2 f7f1 3845f3 7c22 807df35a 7f1c 8d53ff }
            // n = 7, score = 200
            //   31d2                 | xor                 edx, edx
            //   f7f1                 | div                 ecx
            //   3845f3               | cmp                 byte ptr [ebp - 0xd], al
            //   7c22                 | jl                  0x24
            //   807df35a             | cmp                 byte ptr [ebp - 0xd], 0x5a
            //   7f1c                 | jg                  0x1e
            //   8d53ff               | lea                 edx, [ebx - 1]

        $sequence_5 = { a1???????? 8a8d84fdffff d3e0 8d55a8 01d0 89442404 893424 }
            // n = 7, score = 200
            //   a1????????           |                     
            //   8a8d84fdffff         | mov                 cl, byte ptr [ebp - 0x27c]
            //   d3e0                 | shl                 eax, cl
            //   8d55a8               | lea                 edx, [ebp - 0x58]
            //   01d0                 | add                 eax, edx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   893424               | mov                 dword ptr [esp], esi

        $sequence_6 = { c744240c00000000 c744240801000000 c744240400000040 8b5514 891424 ff15???????? 83ec1c }
            // n = 7, score = 200
            //   c744240c00000000     | mov                 dword ptr [esp + 0xc], 0
            //   c744240801000000     | mov                 dword ptr [esp + 8], 1
            //   c744240400000040     | mov                 dword ptr [esp + 4], 0x40000000
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   891424               | mov                 dword ptr [esp], edx
            //   ff15????????         |                     
            //   83ec1c               | sub                 esp, 0x1c

        $sequence_7 = { ba51040000 a1???????? e8???????? c7042488130000 }
            // n = 4, score = 200
            //   ba51040000           | mov                 edx, 0x451
            //   a1????????           |                     
            //   e8????????           |                     
            //   c7042488130000       | mov                 dword ptr [esp], 0x1388

        $sequence_8 = { 750d 8b45d8 8b955cfeffff 8902 }
            // n = 4, score = 200
            //   750d                 | jne                 0xf
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8b955cfeffff         | mov                 edx, dword ptr [ebp - 0x1a4]
            //   8902                 | mov                 dword ptr [edx], eax

        $sequence_9 = { 8d8340120000 890424 e8???????? c7831c12000005000000 }
            // n = 4, score = 200
            //   8d8340120000         | lea                 eax, [ebx + 0x1240]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   c7831c12000005000000     | mov    dword ptr [ebx + 0x121c], 5

    condition:
        7 of them and filesize < 90112
}