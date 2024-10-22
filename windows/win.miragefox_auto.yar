rule win_miragefox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.miragefox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miragefox"
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
        $sequence_0 = { bf20800000 3bcf 0f85c7fcffff 57 8d85947cffff 6a00 50 }
            // n = 7, score = 100
            //   bf20800000           | mov                 edi, 0x8020
            //   3bcf                 | cmp                 ecx, edi
            //   0f85c7fcffff         | jne                 0xfffffccd
            //   57                   | push                edi
            //   8d85947cffff         | lea                 eax, [ebp - 0x836c]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_1 = { e8???????? 83660c00 59 59 5f 5b 8b4df4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83660c00             | and                 dword ptr [esi + 0xc], 0
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_2 = { 5b c9 c20400 55 8bec 8b451c }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]

        $sequence_3 = { 03c8 6bc90b 42 8bc1 8a0a }
            // n = 5, score = 100
            //   03c8                 | add                 ecx, eax
            //   6bc90b               | imul                ecx, ecx, 0xb
            //   42                   | inc                 edx
            //   8bc1                 | mov                 eax, ecx
            //   8a0a                 | mov                 cl, byte ptr [edx]

        $sequence_4 = { e8???????? 83c420 56 e8???????? 8bcb c70424???????? e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   c70424????????       |                     
            //   e8????????           |                     

        $sequence_5 = { 2bf8 897df4 85d2 7412 6a52 8bf7 59 }
            // n = 7, score = 100
            //   2bf8                 | sub                 edi, eax
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   85d2                 | test                edx, edx
            //   7412                 | je                  0x14
            //   6a52                 | push                0x52
            //   8bf7                 | mov                 esi, edi
            //   59                   | pop                 ecx

        $sequence_6 = { 8d8db0fbffff e8???????? 8365fc00 b808880000 }
            // n = 4, score = 100
            //   8d8db0fbffff         | lea                 ecx, [ebp - 0x450]
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   b808880000           | mov                 eax, 0x8808

        $sequence_7 = { 50 e8???????? 83e804 8975ec 8d8e08880000 8d7b04 8930 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83e804               | sub                 eax, 4
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   8d8e08880000         | lea                 ecx, [esi + 0x8808]
            //   8d7b04               | lea                 edi, [ebx + 4]
            //   8930                 | mov                 dword ptr [eax], esi

        $sequence_8 = { 50 8b45d8 66895dce 66895dd0 ff30 e8???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   66895dce             | mov                 word ptr [ebp - 0x32], bx
            //   66895dd0             | mov                 word ptr [ebp - 0x30], bx
            //   ff30                 | push                dword ptr [eax]
            //   e8????????           |                     

        $sequence_9 = { 88450a 0fb6c0 f68041f72a0004 744f 6a01 }
            // n = 5, score = 100
            //   88450a               | mov                 byte ptr [ebp + 0xa], al
            //   0fb6c0               | movzx               eax, al
            //   f68041f72a0004       | test                byte ptr [eax + 0x2af741], 4
            //   744f                 | je                  0x51
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 286720
}