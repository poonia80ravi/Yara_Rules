rule win_qakbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.qakbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot"
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
        $sequence_0 = { c9 c3 55 8bec 81ecc4090000 }
            // n = 5, score = 4900
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ecc4090000         | sub                 esp, 0x9c4

        $sequence_1 = { 33c0 7402 ebfa e8???????? }
            // n = 4, score = 4800
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   e8????????           |                     

        $sequence_2 = { 50 e8???????? 8b06 47 }
            // n = 4, score = 4800
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   47                   | inc                 edi

        $sequence_3 = { 740d 8d45fc 6a00 50 e8???????? 59 59 }
            // n = 7, score = 4800
            //   740d                 | je                  0xf
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_4 = { ebfa eb06 33c0 7402 }
            // n = 4, score = 4600
            //   ebfa                 | jmp                 0xfffffffc
            //   eb06                 | jmp                 8
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_5 = { 7402 ebfa 33c0 7402 }
            // n = 4, score = 4600
            //   7402                 | je                  4
            //   ebfa                 | jmp                 0xfffffffc
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_6 = { 50 ff5508 8bf0 59 }
            // n = 4, score = 4300
            //   50                   | push                eax
            //   ff5508               | call                dword ptr [ebp + 8]
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_7 = { 57 ff15???????? 33c0 85f6 0f94c0 }
            // n = 5, score = 4100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   85f6                 | test                esi, esi
            //   0f94c0               | sete                al

        $sequence_8 = { e8???????? 83c410 33c0 7402 }
            // n = 4, score = 4000
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_9 = { c1e814 40 c1e014 50 }
            // n = 4, score = 4000
            //   c1e814               | shr                 eax, 0x14
            //   40                   | inc                 eax
            //   c1e014               | shl                 eax, 0x14
            //   50                   | push                eax

        $sequence_10 = { c3 33c9 3d80000000 0f94c1 }
            // n = 4, score = 3900
            //   c3                   | ret                 
            //   33c9                 | xor                 ecx, ecx
            //   3d80000000           | cmp                 eax, 0x80
            //   0f94c1               | sete                cl

        $sequence_11 = { 6a00 6a02 ff15???????? 8bf8 83c8ff 3bf8 }
            // n = 6, score = 3900
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83c8ff               | or                  eax, 0xffffffff
            //   3bf8                 | cmp                 edi, eax

        $sequence_12 = { c74508???????? e8???????? 85c0 7d08 83c8ff e9???????? }
            // n = 6, score = 3900
            //   c74508????????       |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7d08                 | jge                 0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     

        $sequence_13 = { 750c 57 ff15???????? 6afe 58 }
            // n = 5, score = 3900
            //   750c                 | jne                 0xe
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6afe                 | push                -2
            //   58                   | pop                 eax

        $sequence_14 = { 8d853cf6ffff 50 6a0c 6a0a }
            // n = 4, score = 3800
            //   8d853cf6ffff         | lea                 eax, [ebp - 0x9c4]
            //   50                   | push                eax
            //   6a0c                 | push                0xc
            //   6a0a                 | push                0xa

        $sequence_15 = { 85c0 750a 33c0 7402 }
            // n = 4, score = 3700
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   33c0                 | xor                 eax, eax
            //   7402                 | je                  4

        $sequence_16 = { 6a00 58 0f95c0 40 50 }
            // n = 5, score = 3700
            //   6a00                 | push                0
            //   58                   | pop                 eax
            //   0f95c0               | setne               al
            //   40                   | inc                 eax
            //   50                   | push                eax

        $sequence_17 = { 837d0800 7507 c74508???????? e8???????? }
            // n = 4, score = 3600
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7507                 | jne                 9
            //   c74508????????       |                     
            //   e8????????           |                     

        $sequence_18 = { 7506 837dec00 740f 817de800000080 }
            // n = 4, score = 3600
            //   7506                 | jne                 8
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0
            //   740f                 | je                  0x11
            //   817de800000080       | cmp                 dword ptr [ebp - 0x18], 0x80000000

        $sequence_19 = { ff750c 8d85d8feffff 50 ff5508 }
            // n = 4, score = 3500
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d85d8feffff         | lea                 eax, [ebp - 0x128]
            //   50                   | push                eax
            //   ff5508               | call                dword ptr [ebp + 8]

        $sequence_20 = { 83c40c 33c0 5b 5f 5e c9 c3 }
            // n = 7, score = 3500
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_21 = { 01c1 81e1ffff0000 83c101 8b442474 }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   83c101               | add                 ecx, 1
            //   8b442474             | mov                 eax, dword ptr [esp + 0x74]

        $sequence_22 = { 00e9 8b55e4 880c1a 8a4df3 }
            // n = 4, score = 100
            //   00e9                 | add                 cl, ch
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   880c1a               | mov                 byte ptr [edx + ebx], cl
            //   8a4df3               | mov                 cl, byte ptr [ebp - 0xd]

        $sequence_23 = { 01c1 894c2430 e9???????? 55 }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   894c2430             | mov                 dword ptr [esp + 0x30], ecx
            //   e9????????           |                     
            //   55                   | push                ebp

        $sequence_24 = { 00ca 66897c2446 31f6 8974244c }
            // n = 4, score = 100
            //   00ca                 | add                 dl, cl
            //   66897c2446           | mov                 word ptr [esp + 0x46], di
            //   31f6                 | xor                 esi, esi
            //   8974244c             | mov                 dword ptr [esp + 0x4c], esi

        $sequence_25 = { 01c1 8b442448 01c8 8944243c }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]
            //   01c8                 | add                 eax, ecx
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax

        $sequence_26 = { 01c1 894c2404 8b442404 8d65fc }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8d65fc               | lea                 esp, [ebp - 4]

        $sequence_27 = { 01c1 21d1 8a442465 f6642465 }
            // n = 4, score = 100
            //   01c1                 | add                 ecx, eax
            //   21d1                 | and                 ecx, edx
            //   8a442465             | mov                 al, byte ptr [esp + 0x65]
            //   f6642465             | mul                 byte ptr [esp + 0x65]

        $sequence_28 = { 00e9 884c0451 83c001 39d0 }
            // n = 4, score = 100
            //   00e9                 | add                 cl, ch
            //   884c0451             | mov                 byte ptr [esp + eax + 0x51], cl
            //   83c001               | add                 eax, 1
            //   39d0                 | cmp                 eax, edx

    condition:
        7 of them and filesize < 958464
}