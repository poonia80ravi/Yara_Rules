rule win_wormhole_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.wormhole."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wormhole"
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
        $sequence_0 = { 7453 3d03000100 7529 8b442418 668b4c241c 8b15???????? 6a00 }
            // n = 7, score = 200
            //   7453                 | je                  0x55
            //   3d03000100           | cmp                 eax, 0x10003
            //   7529                 | jne                 0x2b
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   668b4c241c           | mov                 cx, word ptr [esp + 0x1c]
            //   8b15????????         |                     
            //   6a00                 | push                0

        $sequence_1 = { 8d542418 6a0f 52 56 e8???????? 83c40c }
            // n = 6, score = 200
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   6a0f                 | push                0xf
            //   52                   | push                edx
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_2 = { 83c404 85c9 66a3???????? 7449 83f9ff 7444 }
            // n = 6, score = 200
            //   83c404               | add                 esp, 4
            //   85c9                 | test                ecx, ecx
            //   66a3????????         |                     
            //   7449                 | je                  0x4b
            //   83f9ff               | cmp                 ecx, -1
            //   7444                 | je                  0x46

        $sequence_3 = { 6808000100 50 e8???????? 83c414 }
            // n = 4, score = 200
            //   6808000100           | push                0x10008
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_4 = { 687f660440 56 ff15???????? 83f8ff 7440 8b442408 }
            // n = 6, score = 200
            //   687f660440           | push                0x4004667f
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   7440                 | je                  0x42
            //   8b442408             | mov                 eax, dword ptr [esp + 8]

        $sequence_5 = { 7544 8b542418 8d4c2408 6a10 51 8d442424 }
            // n = 6, score = 200
            //   7544                 | jne                 0x46
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   6a10                 | push                0x10
            //   51                   | push                ecx
            //   8d442424             | lea                 eax, [esp + 0x24]

        $sequence_6 = { 745a 85c0 74e5 8d442408 }
            // n = 4, score = 200
            //   745a                 | je                  0x5c
            //   85c0                 | test                eax, eax
            //   74e5                 | je                  0xffffffe7
            //   8d442408             | lea                 eax, [esp + 8]

        $sequence_7 = { 53 ff15???????? 85c0 7e0f }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7e0f                 | jle                 0x11

        $sequence_8 = { 88440c00 41 83f910 72ee 56 }
            // n = 5, score = 200
            //   88440c00             | mov                 byte ptr [esp + ecx], al
            //   41                   | inc                 ecx
            //   83f910               | cmp                 ecx, 0x10
            //   72ee                 | jb                  0xfffffff0
            //   56                   | push                esi

        $sequence_9 = { eb2b 3d06000100 7524 8b0d???????? }
            // n = 4, score = 200
            //   eb2b                 | jmp                 0x2d
            //   3d06000100           | cmp                 eax, 0x10006
            //   7524                 | jne                 0x26
            //   8b0d????????         |                     

    condition:
        7 of them and filesize < 99576
}