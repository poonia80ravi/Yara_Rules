rule win_wpbrutebot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.wpbrutebot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wpbrutebot"
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
        $sequence_0 = { e8???????? c785acfeffff00000000 c645fcca 8b8dbcfeffff 85c9 7415 8b01 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c785acfeffff00000000     | mov    dword ptr [ebp - 0x154], 0
            //   c645fcca             | mov                 byte ptr [ebp - 4], 0xca
            //   8b8dbcfeffff         | mov                 ecx, dword ptr [ebp - 0x144]
            //   85c9                 | test                ecx, ecx
            //   7415                 | je                  0x17
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_1 = { 8b44243c c60000 8d442424 50 ffb3d00c0000 57 e8???????? }
            // n = 7, score = 100
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]
            //   c60000               | mov                 byte ptr [eax], 0
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   50                   | push                eax
            //   ffb3d00c0000         | push                dword ptr [ebx + 0xcd0]
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_2 = { baff000000 d3fa 23d0 8a82f0096200 0fb6c8 8806 85ff }
            // n = 7, score = 100
            //   baff000000           | mov                 edx, 0xff
            //   d3fa                 | sar                 edx, cl
            //   23d0                 | and                 edx, eax
            //   8a82f0096200         | mov                 al, byte ptr [edx + 0x6209f0]
            //   0fb6c8               | movzx               ecx, al
            //   8806                 | mov                 byte ptr [esi], al
            //   85ff                 | test                edi, edi

        $sequence_3 = { 8d8d3cf4ffff e8???????? c645fcfd 68???????? 8bd0 8d8d54f4ffff e8???????? }
            // n = 7, score = 100
            //   8d8d3cf4ffff         | lea                 ecx, [ebp - 0xbc4]
            //   e8????????           |                     
            //   c645fcfd             | mov                 byte ptr [ebp - 4], 0xfd
            //   68????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d8d54f4ffff         | lea                 ecx, [ebp - 0xbac]
            //   e8????????           |                     

        $sequence_4 = { ff7500 e8???????? 8b4c241c 83c40c 83ceff c70137000000 eb39 }
            // n = 7, score = 100
            //   ff7500               | push                dword ptr [ebp]
            //   e8????????           |                     
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   83c40c               | add                 esp, 0xc
            //   83ceff               | or                  esi, 0xffffffff
            //   c70137000000         | mov                 dword ptr [ecx], 0x37
            //   eb39                 | jmp                 0x3b

        $sequence_5 = { e8???????? 83c404 8d8d74fcffff 50 e8???????? 8d8d80efffff e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d8d74fcffff         | lea                 ecx, [ebp - 0x38c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8d80efffff         | lea                 ecx, [ebp - 0x1080]
            //   e8????????           |                     

        $sequence_6 = { e8???????? ff36 e8???????? 8d4660 50 56 6a0f }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     
            //   8d4660               | lea                 eax, [esi + 0x60]
            //   50                   | push                eax
            //   56                   | push                esi
            //   6a0f                 | push                0xf

        $sequence_7 = { 57 e8???????? 83c40c 80bf1d0b000000 7407 6a01 e9???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   80bf1d0b000000       | cmp                 byte ptr [edi + 0xb1d], 0
            //   7407                 | je                  9
            //   6a01                 | push                1
            //   e9????????           |                     

        $sequence_8 = { c3 8d442404 50 56 6a02 ff74241c ff15???????? }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8d442404             | lea                 eax, [esp + 4]
            //   50                   | push                eax
            //   56                   | push                esi
            //   6a02                 | push                2
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   ff15????????         |                     

        $sequence_9 = { c3 53 8b9ef8050000 55 85db 7408 8baeb4050000 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   8b9ef8050000         | mov                 ebx, dword ptr [esi + 0x5f8]
            //   55                   | push                ebp
            //   85db                 | test                ebx, ebx
            //   7408                 | je                  0xa
            //   8baeb4050000         | mov                 ebp, dword ptr [esi + 0x5b4]

    condition:
        7 of them and filesize < 5134336
}