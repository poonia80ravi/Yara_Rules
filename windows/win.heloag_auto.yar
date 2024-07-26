rule win_heloag_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.heloag."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heloag"
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
        $sequence_0 = { 68???????? 52 ffd6 8d85b0fdffff 6a01 8d8dacfcffff }
            // n = 6, score = 300
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   8d85b0fdffff         | lea                 eax, [ebp - 0x250]
            //   6a01                 | push                1
            //   8d8dacfcffff         | lea                 ecx, [ebp - 0x354]

        $sequence_1 = { 53 6a01 6a02 e8???????? 68???????? }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   e8????????           |                     
            //   68????????           |                     

        $sequence_2 = { 7437 8d55f4 52 ff15???????? }
            // n = 4, score = 300
            //   7437                 | je                  0x39
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_3 = { 83e103 50 68???????? f3a4 ffd3 50 }
            // n = 6, score = 300
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax
            //   68????????           |                     
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ffd3                 | call                ebx
            //   50                   | push                eax

        $sequence_4 = { 55 8bec 81ec90010000 53 56 57 90 }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec90010000         | sub                 esp, 0x190
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   90                   | nop                 

        $sequence_5 = { b940000000 f3ab 66ab 8d9578ffffff aa 52 8d85acfdffff }
            // n = 7, score = 300
            //   b940000000           | mov                 ecx, 0x40
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8d9578ffffff         | lea                 edx, [ebp - 0x88]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   52                   | push                edx
            //   8d85acfdffff         | lea                 eax, [ebp - 0x254]

        $sequence_6 = { 3b75ec 7d2b 6a00 6a01 6a02 }
            // n = 5, score = 300
            //   3b75ec               | cmp                 esi, dword ptr [ebp - 0x14]
            //   7d2b                 | jge                 0x2d
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a02                 | push                2

        $sequence_7 = { 50 f3a4 68???????? ffd3 50 ff15???????? }
            // n = 6, score = 300
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   68????????           |                     
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { 741f 8b7c2418 8bcb 8bd1 53 c1e902 f3a5 }
            // n = 7, score = 200
            //   741f                 | je                  0x21
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   8bcb                 | mov                 ecx, ebx
            //   8bd1                 | mov                 edx, ecx
            //   53                   | push                ebx
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_9 = { 8a442413 6a00 8bce 8806 }
            // n = 4, score = 200
            //   8a442413             | mov                 al, byte ptr [esp + 0x13]
            //   6a00                 | push                0
            //   8bce                 | mov                 ecx, esi
            //   8806                 | mov                 byte ptr [esi], al

        $sequence_10 = { 3bc5 7505 a1???????? 50 }
            // n = 4, score = 200
            //   3bc5                 | cmp                 eax, ebp
            //   7505                 | jne                 7
            //   a1????????           |                     
            //   50                   | push                eax

        $sequence_11 = { 7505 a1???????? 894304 8b5608 895308 8b4e0c 894b0c }
            // n = 7, score = 200
            //   7505                 | jne                 7
            //   a1????????           |                     
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   895308               | mov                 dword ptr [ebx + 8], edx
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   894b0c               | mov                 dword ptr [ebx + 0xc], ecx

        $sequence_12 = { 8bcf 52 6a00 50 }
            // n = 4, score = 200
            //   8bcf                 | mov                 ecx, edi
            //   52                   | push                edx
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_13 = { 742d 8b7604 85f6 7506 8b35???????? 8b7b04 }
            // n = 6, score = 200
            //   742d                 | je                  0x2f
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   85f6                 | test                esi, esi
            //   7506                 | jne                 8
            //   8b35????????         |                     
            //   8b7b04               | mov                 edi, dword ptr [ebx + 4]

        $sequence_14 = { 53 8bcd ff15???????? 6a00 6a00 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   8bcd                 | mov                 ecx, ebp
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_15 = { 8d4c2418 53 ff15???????? 84c0 741f 8b7c2418 }
            // n = 6, score = 200
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   84c0                 | test                al, al
            //   741f                 | je                  0x21
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]

    condition:
        7 of them and filesize < 401408
}