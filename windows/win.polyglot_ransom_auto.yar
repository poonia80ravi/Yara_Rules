rule win_polyglot_ransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.polyglot_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyglot_ransom"
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
        $sequence_0 = { 8b8dcc80ffff e8???????? 59 50 8985c480ffff e8???????? 8bf0 }
            // n = 7, score = 100
            //   8b8dcc80ffff         | mov                 ecx, dword ptr [ebp - 0x7f34]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   8985c480ffff         | mov                 dword ptr [ebp - 0x7f3c], eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { 0f95c2 66c7010b00 4a 66895108 ff75f0 ff15???????? 8b45ec }
            // n = 7, score = 100
            //   0f95c2               | setne               dl
            //   66c7010b00           | mov                 word ptr [ecx], 0xb
            //   4a                   | dec                 edx
            //   66895108             | mov                 word ptr [ecx + 8], dx
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_2 = { 834dfcff 395df0 7409 ff75ec 53 e8???????? b805400080 }
            // n = 7, score = 100
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   395df0               | cmp                 dword ptr [ebp - 0x10], ebx
            //   7409                 | je                  0xb
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   b805400080           | mov                 eax, 0x80004005

        $sequence_3 = { 822d????????d0 bdd0ba20d0 a0???????? d181d0b8d0b9 d181d0bad0b8 d18520d0b1d0 b0d0 }
            // n = 7, score = 100
            //   822d????????d0       |                     
            //   bdd0ba20d0           | mov                 ebp, 0xd020bad0
            //   a0????????           |                     
            //   d181d0b8d0b9         | rol                 dword ptr [ecx - 0x462f4730], 1
            //   d181d0bad0b8         | rol                 dword ptr [ecx - 0x472f4530], 1
            //   d18520d0b1d0         | rol                 dword ptr [ebp - 0x2f4e2fe0], 1
            //   b0d0                 | mov                 al, 0xd0

        $sequence_4 = { 8bcc 50 e8???????? 51 c645fc0c 8bcc 8965dc }
            // n = 7, score = 100
            //   8bcc                 | mov                 ecx, esp
            //   50                   | push                eax
            //   e8????????           |                     
            //   51                   | push                ecx
            //   c645fc0c             | mov                 byte ptr [ebp - 4], 0xc
            //   8bcc                 | mov                 ecx, esp
            //   8965dc               | mov                 dword ptr [ebp - 0x24], esp

        $sequence_5 = { 66696c65735f69 7427 20636c 61 7373 3d22706167 652220 }
            // n = 7, score = 100
            //   66696c65735f69       | imul                bp, word ptr [ebp + 0x73], 0x695f
            //   7427                 | je                  0x29
            //   20636c               | and                 byte ptr [ebx + 0x6c], ah
            //   61                   | popal               
            //   7373                 | jae                 0x75
            //   3d22706167           | cmp                 eax, 0x67617022
            //   652220               | and                 ah, byte ptr gs:[eax]

        $sequence_6 = { 8bd8 41 33c0 3bf0 57 894dfc 0f8456010000 }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   41                   | inc                 ecx
            //   33c0                 | xor                 eax, eax
            //   3bf0                 | cmp                 esi, eax
            //   57                   | push                edi
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   0f8456010000         | je                  0x15c

        $sequence_7 = { b5d1 88d0 b8d184d180 d0bed0b2d0b0 d0bdd0b8d18f }
            // n = 5, score = 100
            //   b5d1                 | mov                 ch, 0xd1
            //   88d0                 | mov                 al, dl
            //   b8d184d180           | mov                 eax, 0x80d184d1
            //   d0bed0b2d0b0         | sar                 byte ptr [esi - 0x4f2f4d30], 1
            //   d0bdd0b8d18f         | sar                 byte ptr [ebp - 0x702e4730], 1

        $sequence_8 = { 0fb64524 8945e8 0fb64525 8945ec 0fb64526 8945f0 8b4510 }
            // n = 7, score = 100
            //   0fb64524             | movzx               eax, byte ptr [ebp + 0x24]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   0fb64525             | movzx               eax, byte ptr [ebp + 0x25]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   0fb64526             | movzx               eax, byte ptr [ebp + 0x26]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_9 = { 7573 64223e 3c2f 7370 61 6e 3e20646f6c }
            // n = 7, score = 100
            //   7573                 | jne                 0x75
            //   64223e               | and                 bh, byte ptr fs:[esi]
            //   3c2f                 | cmp                 al, 0x2f
            //   7370                 | jae                 0x72
            //   61                   | popal               
            //   6e                   | outsb               dx, byte ptr [esi]
            //   3e20646f6c           | and                 byte ptr ds:[edi + ebp*2 + 0x6c], ah

    condition:
        7 of them and filesize < 1392640
}