rule win_onliner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.onliner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.onliner"
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
        $sequence_0 = { 000c4b 41 001e 4b }
            // n = 4, score = 100
            //   000c4b               | add                 byte ptr [ebx + ecx*2], cl
            //   41                   | inc                 ecx
            //   001e                 | add                 byte ptr [esi], bl
            //   4b                   | dec                 ebx

        $sequence_1 = { 001c87 42 002483 42 }
            // n = 4, score = 100
            //   001c87               | add                 byte ptr [edi + eax*4], bl
            //   42                   | inc                 edx
            //   002483               | add                 byte ptr [ebx + eax*4], ah
            //   42                   | inc                 edx

        $sequence_2 = { 0003 9a4100539a4100 879a4100d19a 41 }
            // n = 4, score = 100
            //   0003                 | add                 byte ptr [ebx], al
            //   9a4100539a4100       | lcall               0x41:0x9a530041
            //   879a4100d19a         | xchg                dword ptr [edx - 0x652effbf], ebx
            //   41                   | inc                 ecx

        $sequence_3 = { 001c83 42 00a887420014 834200bc }
            // n = 4, score = 100
            //   001c83               | add                 byte ptr [ebx + eax*4], bl
            //   42                   | inc                 edx
            //   00a887420014         | add                 byte ptr [eax + 0x14004287], ch
            //   834200bc             | add                 dword ptr [edx], -0x44

        $sequence_4 = { 001e 4b 41 0030 }
            // n = 4, score = 100
            //   001e                 | add                 byte ptr [esi], bl
            //   4b                   | dec                 ebx
            //   41                   | inc                 ecx
            //   0030                 | add                 byte ptr [eax], dh

        $sequence_5 = { 0008 874200 fc 8242003c }
            // n = 4, score = 100
            //   0008                 | add                 byte ptr [eax], cl
            //   874200               | xchg                dword ptr [edx], eax
            //   fc                   | cld                 
            //   8242003c             | add                 byte ptr [edx], 0x3c

        $sequence_6 = { 0004054100d005 41 00d0 0541001505 }
            // n = 4, score = 100
            //   0004054100d005       | add                 byte ptr [eax + 0x5d00041], al
            //   41                   | inc                 ecx
            //   00d0                 | add                 al, dl
            //   0541001505           | add                 eax, 0x5150041

        $sequence_7 = { 001c99 41 004999 41 }
            // n = 4, score = 100
            //   001c99               | add                 byte ptr [ecx + ebx*4], bl
            //   41                   | inc                 ecx
            //   004999               | add                 byte ptr [ecx - 0x67], cl
            //   41                   | inc                 ecx

    condition:
        7 of them and filesize < 1736704
}