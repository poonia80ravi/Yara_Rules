rule win_glitch_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.glitch_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glitch_pos"
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
        $sequence_0 = { ff5014 dbe2 898558ffffff 83bd58ffffff00 7d20 6a14 68???????? }
            // n = 7, score = 100
            //   ff5014               | call                dword ptr [eax + 0x14]
            //   dbe2                 | fnclex              
            //   898558ffffff         | mov                 dword ptr [ebp - 0xa8], eax
            //   83bd58ffffff00       | cmp                 dword ptr [ebp - 0xa8], 0
            //   7d20                 | jge                 0x22
            //   6a14                 | push                0x14
            //   68????????           |                     

        $sequence_1 = { 7d20 6a40 68???????? ffb564ffffff ffb560ffffff }
            // n = 5, score = 100
            //   7d20                 | jge                 0x22
            //   6a40                 | push                0x40
            //   68????????           |                     
            //   ffb564ffffff         | push                dword ptr [ebp - 0x9c]
            //   ffb560ffffff         | push                dword ptr [ebp - 0xa0]

        $sequence_2 = { e8???????? e8???????? 8d8520ffffff 50 8d8530ffffff 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   8d8520ffffff         | lea                 eax, [ebp - 0xe0]
            //   50                   | push                eax
            //   8d8530ffffff         | lea                 eax, [ebp - 0xd0]
            //   50                   | push                eax

        $sequence_3 = { c745940a000000 6a10 58 e8???????? 8d7594 8bfc a5 }
            // n = 7, score = 100
            //   c745940a000000       | mov                 dword ptr [ebp - 0x6c], 0xa
            //   6a10                 | push                0x10
            //   58                   | pop                 eax
            //   e8????????           |                     
            //   8d7594               | lea                 esi, [ebp - 0x6c]
            //   8bfc                 | mov                 edi, esp
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_4 = { c745b011600000 6a00 6a40 8d45b0 50 8d45d0 }
            // n = 6, score = 100
            //   c745b011600000       | mov                 dword ptr [ebp - 0x50], 0x6011
            //   6a00                 | push                0
            //   6a40                 | push                0x40
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   50                   | push                eax
            //   8d45d0               | lea                 eax, [ebp - 0x30]

        $sequence_5 = { 8b00 ff7508 ff9020030000 50 8d45e4 50 e8???????? }
            // n = 7, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff9020030000         | call                dword ptr [eax + 0x320]
            //   50                   | push                eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 8b4508 8b00 ff7508 ff9040030000 50 8d45cc 50 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff9040030000         | call                dword ptr [eax + 0x340]
            //   50                   | push                eax
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax

        $sequence_7 = { c7850cffffff02000000 8d852cffffff 50 8d851cffffff 50 8d850cffffff 50 }
            // n = 7, score = 100
            //   c7850cffffff02000000     | mov    dword ptr [ebp - 0xf4], 2
            //   8d852cffffff         | lea                 eax, [ebp - 0xd4]
            //   50                   | push                eax
            //   8d851cffffff         | lea                 eax, [ebp - 0xe4]
            //   50                   | push                eax
            //   8d850cffffff         | lea                 eax, [ebp - 0xf4]
            //   50                   | push                eax

        $sequence_8 = { dbe2 89851cfeffff 83bd1cfeffff00 7d20 6a40 }
            // n = 5, score = 100
            //   dbe2                 | fnclex              
            //   89851cfeffff         | mov                 dword ptr [ebp - 0x1e4], eax
            //   83bd1cfeffff00       | cmp                 dword ptr [ebp - 0x1e4], 0
            //   7d20                 | jge                 0x22
            //   6a40                 | push                0x40

        $sequence_9 = { 8d45e0 50 e8???????? 8945c8 8d45dc 50 ff75ec }
            // n = 7, score = 100
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   ff75ec               | push                dword ptr [ebp - 0x14]

    condition:
        7 of them and filesize < 1024000
}