rule win_derusbi_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.derusbi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.derusbi"
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
        $sequence_0 = { ff15???????? ffb574ffffff e9???????? 8b4590 8b4d84 8901 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   ffb574ffffff         | push                dword ptr [ebp - 0x8c]
            //   e9????????           |                     
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   8b4d84               | mov                 ecx, dword ptr [ebp - 0x7c]
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_1 = { 8d4618 6a5c 50 897c2414 897c2418 ffd3 59 }
            // n = 7, score = 200
            //   8d4618               | lea                 eax, [esi + 0x18]
            //   6a5c                 | push                0x5c
            //   50                   | push                eax
            //   897c2414             | mov                 dword ptr [esp + 0x14], edi
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   ffd3                 | call                ebx
            //   59                   | pop                 ecx

        $sequence_2 = { 68???????? e8???????? 8b4508 89859cf8ffff c785a0f8ffff64000000 33f6 89b5b8f8ffff }
            // n = 7, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   89859cf8ffff         | mov                 dword ptr [ebp - 0x764], eax
            //   c785a0f8ffff64000000     | mov    dword ptr [ebp - 0x760], 0x64
            //   33f6                 | xor                 esi, esi
            //   89b5b8f8ffff         | mov                 dword ptr [ebp - 0x748], esi

        $sequence_3 = { ff7508 ff15???????? 8bf0 59 85f6 740f ff7508 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx
            //   85f6                 | test                esi, esi
            //   740f                 | je                  0x11
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_4 = { 33c0 668906 8b4744 898682000000 8b4750 898686000000 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   668906               | mov                 word ptr [esi], ax
            //   8b4744               | mov                 eax, dword ptr [edi + 0x44]
            //   898682000000         | mov                 dword ptr [esi + 0x82], eax
            //   8b4750               | mov                 eax, dword ptr [edi + 0x50]
            //   898686000000         | mov                 dword ptr [esi + 0x86], eax

        $sequence_5 = { ffd7 8b85c0fbffff 33c9 83c40c 668988fe010000 6a40 8d8dc8fbffff }
            // n = 7, score = 200
            //   ffd7                 | call                edi
            //   8b85c0fbffff         | mov                 eax, dword ptr [ebp - 0x440]
            //   33c9                 | xor                 ecx, ecx
            //   83c40c               | add                 esp, 0xc
            //   668988fe010000       | mov                 word ptr [eax + 0x1fe], cx
            //   6a40                 | push                0x40
            //   8d8dc8fbffff         | lea                 ecx, [ebp - 0x438]

        $sequence_6 = { 59 85c0 743d 57 ffd6 50 8d85fcfbffff }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   743d                 | je                  0x3f
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]

        $sequence_7 = { 8d4608 53 50 c706???????? 895e04 ff15???????? 8b3d???????? }
            // n = 7, score = 200
            //   8d4608               | lea                 eax, [esi + 8]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   c706????????         |                     
            //   895e04               | mov                 dword ptr [esi + 4], ebx
            //   ff15????????         |                     
            //   8b3d????????         |                     

        $sequence_8 = { 50 ffd7 8d85e8fbffff 50 ffd3 83c40c 6683bc45e6fbffff5c }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8d85e8fbffff         | lea                 eax, [ebp - 0x418]
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   83c40c               | add                 esp, 0xc
            //   6683bc45e6fbffff5c     | cmp    word ptr [ebp + eax*2 - 0x41a], 0x5c

        $sequence_9 = { 33c0 e9???????? 8b869c000000 8b800c010000 6800001000 }
            // n = 5, score = 200
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8b869c000000         | mov                 eax, dword ptr [esi + 0x9c]
            //   8b800c010000         | mov                 eax, dword ptr [eax + 0x10c]
            //   6800001000           | push                0x100000

    condition:
        7 of them and filesize < 360448
}