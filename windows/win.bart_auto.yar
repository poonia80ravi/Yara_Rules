rule win_bart_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.bart."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bart"
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
        $sequence_0 = { 8a01 41 84c0 75f9 6a00 8d458c 2bcb }
            // n = 7, score = 100
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   6a00                 | push                0
            //   8d458c               | lea                 eax, [ebp - 0x74]
            //   2bcb                 | sub                 ecx, ebx

        $sequence_1 = { 8bce 8b45e0 4b 895dd8 8b00 }
            // n = 5, score = 100
            //   8bce                 | mov                 ecx, esi
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   4b                   | dec                 ebx
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_2 = { f7d8 8911 83c104 4e 75eb 8b7598 }
            // n = 6, score = 100
            //   f7d8                 | neg                 eax
            //   8911                 | mov                 dword ptr [ecx], edx
            //   83c104               | add                 ecx, 4
            //   4e                   | dec                 esi
            //   75eb                 | jne                 0xffffffed
            //   8b7598               | mov                 esi, dword ptr [ebp - 0x68]

        $sequence_3 = { e8???????? ff75c0 fec8 88443dec ffd3 8365c000 47 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff75c0               | push                dword ptr [ebp - 0x40]
            //   fec8                 | dec                 al
            //   88443dec             | mov                 byte ptr [ebp + edi - 0x14], al
            //   ffd3                 | call                ebx
            //   8365c000             | and                 dword ptr [ebp - 0x40], 0
            //   47                   | inc                 edi

        $sequence_4 = { 83c420 8945b8 8bcb 81c784000000 8d5a08 }
            // n = 5, score = 100
            //   83c420               | add                 esp, 0x20
            //   8945b8               | mov                 dword ptr [ebp - 0x48], eax
            //   8bcb                 | mov                 ecx, ebx
            //   81c784000000         | add                 edi, 0x84
            //   8d5a08               | lea                 ebx, [edx + 8]

        $sequence_5 = { 8d82680e0000 c745ecd0f04000 8945e8 8d75e4 f30f7f45f0 }
            // n = 5, score = 100
            //   8d82680e0000         | lea                 eax, [edx + 0xe68]
            //   c745ecd0f04000       | mov                 dword ptr [ebp - 0x14], 0x40f0d0
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d75e4               | lea                 esi, [ebp - 0x1c]
            //   f30f7f45f0           | movdqu              xmmword ptr [ebp - 0x10], xmm0

        $sequence_6 = { 8d55dc 50 57 8d4d9c e8???????? }
            // n = 5, score = 100
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   50                   | push                eax
            //   57                   | push                edi
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   e8????????           |                     

        $sequence_7 = { 4f 75e7 8b4d0c 33d2 895de0 8d5f06 897de8 }
            // n = 7, score = 100
            //   4f                   | dec                 edi
            //   75e7                 | jne                 0xffffffe9
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   33d2                 | xor                 edx, edx
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   8d5f06               | lea                 ebx, [edi + 6]
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi

        $sequence_8 = { 8b83b0000000 ffd0 0fb603 8d55dc 8bbdbcfeffff 8d4d9c 50 }
            // n = 7, score = 100
            //   8b83b0000000         | mov                 eax, dword ptr [ebx + 0xb0]
            //   ffd0                 | call                eax
            //   0fb603               | movzx               eax, byte ptr [ebx]
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   8bbdbcfeffff         | mov                 edi, dword ptr [ebp - 0x144]
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   50                   | push                eax

        $sequence_9 = { 833802 7411 c705????????00000800 b800000800 eb63 8b45f8 }
            // n = 6, score = 100
            //   833802               | cmp                 dword ptr [eax], 2
            //   7411                 | je                  0x13
            //   c705????????00000800     |     
            //   b800000800           | mov                 eax, 0x80000
            //   eb63                 | jmp                 0x65
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

    condition:
        7 of them and filesize < 163840
}