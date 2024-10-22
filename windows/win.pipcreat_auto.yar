rule win_pipcreat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pipcreat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pipcreat"
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
        $sequence_0 = { 8d8538ffffff 6a28 50 68cc460010 e8???????? 83c40c 6a01 }
            // n = 7, score = 100
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]
            //   6a28                 | push                0x28
            //   50                   | push                eax
            //   68cc460010           | push                0x100046cc
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a01                 | push                1

        $sequence_1 = { 6a10 50 ff35???????? e8???????? 83c418 83f8ff a3???????? }
            // n = 7, score = 100
            //   6a10                 | push                0x10
            //   50                   | push                eax
            //   ff35????????         |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   83f8ff               | cmp                 eax, -1
            //   a3????????           |                     

        $sequence_2 = { 6a14 6814400010 68c8450010 e8???????? }
            // n = 4, score = 100
            //   6a14                 | push                0x14
            //   6814400010           | push                0x10004014
            //   68c8450010           | push                0x100045c8
            //   e8????????           |                     

        $sequence_3 = { 6a00 57 56 ff742418 ff15???????? 56 8bf8 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   ff15????????         |                     
            //   56                   | push                esi
            //   8bf8                 | mov                 edi, eax

        $sequence_4 = { e8???????? 66a1???????? 83c40c 668975f0 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   66a1????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   668975f0             | mov                 word ptr [ebp - 0x10], si

        $sequence_5 = { 8945f0 33c0 8dbdaddeffff 889dacdeffff f3ab }
            // n = 5, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   33c0                 | xor                 eax, eax
            //   8dbdaddeffff         | lea                 edi, [ebp - 0x2153]
            //   889dacdeffff         | mov                 byte ptr [ebp - 0x2154], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_6 = { 56 51 ff35???????? 8d4d10 51 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   51                   | push                ecx
            //   ff35????????         |                     
            //   8d4d10               | lea                 ecx, [ebp + 0x10]
            //   51                   | push                ecx

        $sequence_7 = { 59 391d???????? 0f84e0feffff ff75e8 }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   391d????????         |                     
            //   0f84e0feffff         | je                  0xfffffee6
            //   ff75e8               | push                dword ptr [ebp - 0x18]

        $sequence_8 = { e8???????? 83c40c 6a1e ffd6 5e }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a1e                 | push                0x1e
            //   ffd6                 | call                esi
            //   5e                   | pop                 esi

        $sequence_9 = { 832000 a1???????? 6804400010 6800400010 a3???????? e8???????? ff05???????? }
            // n = 7, score = 100
            //   832000               | and                 dword ptr [eax], 0
            //   a1????????           |                     
            //   6804400010           | push                0x10004004
            //   6800400010           | push                0x10004000
            //   a3????????           |                     
            //   e8????????           |                     
            //   ff05????????         |                     

    condition:
        7 of them and filesize < 65536
}