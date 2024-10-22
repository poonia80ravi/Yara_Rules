rule win_unidentified_044_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_044."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_044"
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
        $sequence_0 = { 7456 3935???????? 0f95c0 0fb6c8 }
            // n = 4, score = 100
            //   7456                 | je                  0x58
            //   3935????????         |                     
            //   0f95c0               | setne               al
            //   0fb6c8               | movzx               ecx, al

        $sequence_1 = { 740c b301 e8???????? a3???????? }
            // n = 4, score = 100
            //   740c                 | je                  0xe
            //   b301                 | mov                 bl, 1
            //   e8????????           |                     
            //   a3????????           |                     

        $sequence_2 = { 56 ff15???????? 881d???????? 84db 750a 5f 5e }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   881d????????         |                     
            //   84db                 | test                bl, bl
            //   750a                 | jne                 0xc
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_3 = { 3bc3 0f843cffffff e8???????? 84c0 }
            // n = 4, score = 100
            //   3bc3                 | cmp                 eax, ebx
            //   0f843cffffff         | je                  0xffffff42
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_4 = { 2bc8 85ff 7ddd 8bb424f4000000 85f6 0f84c3020000 8d9424a8000000 }
            // n = 7, score = 100
            //   2bc8                 | sub                 ecx, eax
            //   85ff                 | test                edi, edi
            //   7ddd                 | jge                 0xffffffdf
            //   8bb424f4000000       | mov                 esi, dword ptr [esp + 0xf4]
            //   85f6                 | test                esi, esi
            //   0f84c3020000         | je                  0x2c9
            //   8d9424a8000000       | lea                 edx, [esp + 0xa8]

        $sequence_5 = { 51 ff15???????? 5f 5e 5d 8ac3 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   8ac3                 | mov                 al, bl

        $sequence_6 = { 83feff 7422 b8d34d6210 f7e6 c1ea06 89542408 }
            // n = 6, score = 100
            //   83feff               | cmp                 esi, -1
            //   7422                 | je                  0x24
            //   b8d34d6210           | mov                 eax, 0x10624dd3
            //   f7e6                 | mul                 esi
            //   c1ea06               | shr                 edx, 6
            //   89542408             | mov                 dword ptr [esp + 8], edx

        $sequence_7 = { 84c0 0f8481000000 8bac2424010000 be08000000 8d542410 52 6a00 }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   0f8481000000         | je                  0x87
            //   8bac2424010000       | mov                 ebp, dword ptr [esp + 0x124]
            //   be08000000           | mov                 esi, 8
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   52                   | push                edx
            //   6a00                 | push                0

        $sequence_8 = { 8a886c637000 8a1404 3aca 750c 40 83f810 }
            // n = 6, score = 100
            //   8a886c637000         | mov                 cl, byte ptr [eax + 0x70636c]
            //   8a1404               | mov                 dl, byte ptr [esp + eax]
            //   3aca                 | cmp                 cl, dl
            //   750c                 | jne                 0xe
            //   40                   | inc                 eax
            //   83f810               | cmp                 eax, 0x10

        $sequence_9 = { 84db 7435 6a04 8d4c240c 51 687fffffff 68ffff0000 }
            // n = 7, score = 100
            //   84db                 | test                bl, bl
            //   7435                 | je                  0x37
            //   6a04                 | push                4
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   51                   | push                ecx
            //   687fffffff           | push                0xffffff7f
            //   68ffff0000           | push                0xffff

    condition:
        7 of them and filesize < 90112
}