rule win_vidar_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.vidar."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { a900400000 7407 8bc6 e8???????? }
            // n = 4, score = 1800
            //   a900400000           | test                eax, 0x4000
            //   7407                 | je                  9
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     

        $sequence_1 = { 8b742408 8b06 8b4804 6a0a }
            // n = 4, score = 1800
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   6a0a                 | push                0xa

        $sequence_2 = { 8dac2404deffff b8fc210000 e8???????? 6aff 68???????? }
            // n = 5, score = 1800
            //   8dac2404deffff       | lea                 ebp, [esp - 0x21fc]
            //   b8fc210000           | mov                 eax, 0x21fc
            //   e8????????           |                     
            //   6aff                 | push                -1
            //   68????????           |                     

        $sequence_3 = { 8d8d1bfeffff e8???????? 50 8d4598 }
            // n = 4, score = 1800
            //   8d8d1bfeffff         | lea                 ecx, [ebp - 0x1e5]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4598               | lea                 eax, [ebp - 0x68]

        $sequence_4 = { 83f8ff 7503 32c0 c3 8b4c2404 8801 b001 }
            // n = 7, score = 1800
            //   83f8ff               | cmp                 eax, -1
            //   7503                 | jne                 5
            //   32c0                 | xor                 al, al
            //   c3                   | ret                 
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   8801                 | mov                 byte ptr [ecx], al
            //   b001                 | mov                 al, 1

        $sequence_5 = { c20800 56 57 8b7c240c 8b07 8bf1 }
            // n = 6, score = 1800
            //   c20800               | ret                 8
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7c240c             | mov                 edi, dword ptr [esp + 0xc]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   8bf1                 | mov                 esi, ecx

        $sequence_6 = { a1???????? 33c5 8985f8210000 53 56 57 }
            // n = 6, score = 1800
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8985f8210000         | mov                 dword ptr [ebp + 0x21f8], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_7 = { c9 c3 8b542408 85d2 7503 33c0 c3 }
            // n = 7, score = 1800
            //   c9                   | leave               
            //   c3                   | ret                 
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   85d2                 | test                edx, edx
            //   7503                 | jne                 5
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_8 = { c20400 56 8bf1 8b4e20 33c0 }
            // n = 5, score = 1800
            //   c20400               | ret                 4
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { a1???????? 895dfc 7305 b8???????? }
            // n = 4, score = 1800
            //   a1????????           |                     
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   7305                 | jae                 7
            //   b8????????           |                     

        $sequence_10 = { 8d4644 6804010000 50 e8???????? 8b4638 }
            // n = 5, score = 1800
            //   8d4644               | lea                 eax, [esi + 0x44]
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4638               | mov                 eax, dword ptr [esi + 0x38]

        $sequence_11 = { c20400 ff742408 e8???????? 59 83f8ff }
            // n = 5, score = 1800
            //   c20400               | ret                 4
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83f8ff               | cmp                 eax, -1

        $sequence_12 = { 8b4804 6a0a 03ce e8???????? 0fb6c0 50 ff742410 }
            // n = 7, score = 1800
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   6a0a                 | push                0xa
            //   03ce                 | add                 ecx, esi
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_13 = { 5e c20400 b001 c3 33c0 }
            // n = 5, score = 1800
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   b001                 | mov                 al, 1
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax

        $sequence_14 = { 8910 8b4120 8910 8b4130 8910 c3 56 }
            // n = 7, score = 1700
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b4120               | mov                 eax, dword ptr [ecx + 0x20]
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b4130               | mov                 eax, dword ptr [ecx + 0x30]
            //   8910                 | mov                 dword ptr [eax], edx
            //   c3                   | ret                 
            //   56                   | push                esi

        $sequence_15 = { dd1c24 6a0b 6a10 e8???????? 83c41c 8be5 }
            // n = 6, score = 200
            //   dd1c24               | fstp                qword ptr [esp]
            //   6a0b                 | push                0xb
            //   6a10                 | push                0x10
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8be5                 | mov                 esp, ebp

        $sequence_16 = { 84c9 75f9 8b4c2410 2bc6 50 52 e8???????? }
            // n = 7, score = 200
            //   84c9                 | test                cl, cl
            //   75f9                 | jne                 0xfffffffb
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   2bc6                 | sub                 eax, esi
            //   50                   | push                eax
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_17 = { dc05???????? 83ec08 dd1c24 83ec08 dd4508 dd1c24 6a0b }
            // n = 7, score = 200
            //   dc05????????         |                     
            //   83ec08               | sub                 esp, 8
            //   dd1c24               | fstp                qword ptr [esp]
            //   83ec08               | sub                 esp, 8
            //   dd4508               | fld                 qword ptr [ebp + 8]
            //   dd1c24               | fstp                qword ptr [esp]
            //   6a0b                 | push                0xb

        $sequence_18 = { dd1c24 6a0b 6a08 e8???????? }
            // n = 4, score = 200
            //   dd1c24               | fstp                qword ptr [esp]
            //   6a0b                 | push                0xb
            //   6a08                 | push                8
            //   e8????????           |                     

        $sequence_19 = { e8???????? 83c408 84c0 740e 68???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   84c0                 | test                al, al
            //   740e                 | je                  0x10
            //   68????????           |                     

        $sequence_20 = { 7507 33c0 e9???????? c745f404000000 }
            // n = 4, score = 100
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   c745f404000000       | mov                 dword ptr [ebp - 0xc], 4

    condition:
        7 of them and filesize < 2793472
}