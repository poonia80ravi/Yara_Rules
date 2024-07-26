rule win_zhcat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.zhcat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zhcat"
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
        $sequence_0 = { 668945d2 395d18 750d 680100007f ff15???????? }
            // n = 5, score = 200
            //   668945d2             | mov                 word ptr [ebp - 0x2e], ax
            //   395d18               | cmp                 dword ptr [ebp + 0x18], ebx
            //   750d                 | jne                 0xf
            //   680100007f           | push                0x7f000001
            //   ff15????????         |                     

        $sequence_1 = { 8945e8 8d45e0 50 56 57 }
            // n = 5, score = 200
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_2 = { ffd7 6a10 8d4dd4 51 }
            // n = 4, score = 200
            //   ffd7                 | call                edi
            //   6a10                 | push                0x10
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   51                   | push                ecx

        $sequence_3 = { 8b149540604100 59 c1e006 59 8a4dff 80c901 884c0204 }
            // n = 7, score = 200
            //   8b149540604100       | mov                 edx, dword ptr [edx*4 + 0x416040]
            //   59                   | pop                 ecx
            //   c1e006               | shl                 eax, 6
            //   59                   | pop                 ecx
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   80c901               | or                  cl, 1
            //   884c0204             | mov                 byte ptr [edx + eax + 4], cl

        $sequence_4 = { 6a01 6a02 ffd7 8bf0 8975f4 3bf3 }
            // n = 6, score = 200
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ffd7                 | call                edi
            //   8bf0                 | mov                 esi, eax
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   3bf3                 | cmp                 esi, ebx

        $sequence_5 = { 56 ff750c 68???????? 57 e8???????? 33f6 83c40c }
            // n = 7, score = 200
            //   56                   | push                esi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   33f6                 | xor                 esi, esi
            //   83c40c               | add                 esp, 0xc

        $sequence_6 = { 4a 4a 740a 4a 7516 b9???????? }
            // n = 6, score = 200
            //   4a                   | dec                 edx
            //   4a                   | dec                 edx
            //   740a                 | je                  0xc
            //   4a                   | dec                 edx
            //   7516                 | jne                 0x18
            //   b9????????           |                     

        $sequence_7 = { 3974241c 7425 ebbc 3bc6 }
            // n = 4, score = 200
            //   3974241c             | cmp                 dword ptr [esp + 0x1c], esi
            //   7425                 | je                  0x27
            //   ebbc                 | jmp                 0xffffffbe
            //   3bc6                 | cmp                 eax, esi

        $sequence_8 = { 33db 85c9 7416 8bc3 }
            // n = 4, score = 200
            //   33db                 | xor                 ebx, ebx
            //   85c9                 | test                ecx, ecx
            //   7416                 | je                  0x18
            //   8bc3                 | mov                 eax, ebx

        $sequence_9 = { 7407 68???????? ebd3 39742418 7507 68???????? ebc6 }
            // n = 7, score = 200
            //   7407                 | je                  9
            //   68????????           |                     
            //   ebd3                 | jmp                 0xffffffd5
            //   39742418             | cmp                 dword ptr [esp + 0x18], esi
            //   7507                 | jne                 9
            //   68????????           |                     
            //   ebc6                 | jmp                 0xffffffc8

    condition:
        7 of them and filesize < 376832
}