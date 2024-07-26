rule win_webc2_bolid_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webc2_bolid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
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
        $sequence_0 = { 8b4dcc 8945d0 33f6 c6040100 397344 }
            // n = 5, score = 100
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   33f6                 | xor                 esi, esi
            //   c6040100             | mov                 byte ptr [ecx + eax], 0
            //   397344               | cmp                 dword ptr [ebx + 0x44], esi

        $sequence_1 = { e8???????? 8d8c24d4000000 c684242c02000004 51 8bcd e8???????? 8b15???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8c24d4000000       | lea                 ecx, [esp + 0xd4]
            //   c684242c02000004     | mov                 byte ptr [esp + 0x22c], 4
            //   51                   | push                ecx
            //   8bcd                 | mov                 ecx, ebp
            //   e8????????           |                     
            //   8b15????????         |                     

        $sequence_2 = { 8b45e8 85c0 7505 b8???????? 8b55ec 8d8d54ffffff 51 }
            // n = 7, score = 100
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   b8????????           |                     
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8d8d54ffffff         | lea                 ecx, [ebp - 0xac]
            //   51                   | push                ecx

        $sequence_3 = { c645fc03 8801 e8???????? 8a55f3 }
            // n = 4, score = 100
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8801                 | mov                 byte ptr [ecx], al
            //   e8????????           |                     
            //   8a55f3               | mov                 dl, byte ptr [ebp - 0xd]

        $sequence_4 = { c684243002000006 e8???????? 8d8c24d4000000 c684242c02000004 }
            // n = 4, score = 100
            //   c684243002000006     | mov                 byte ptr [esp + 0x230], 6
            //   e8????????           |                     
            //   8d8c24d4000000       | lea                 ecx, [esp + 0xd4]
            //   c684242c02000004     | mov                 byte ptr [esp + 0x22c], 4

        $sequence_5 = { c645fc16 c6451b5c e8???????? 8d4dd0 }
            // n = 4, score = 100
            //   c645fc16             | mov                 byte ptr [ebp - 4], 0x16
            //   c6451b5c             | mov                 byte ptr [ebp + 0x1b], 0x5c
            //   e8????????           |                     
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]

        $sequence_6 = { eb09 51 e8???????? 83c404 8b442470 }
            // n = 5, score = 100
            //   eb09                 | jmp                 0xb
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b442470             | mov                 eax, dword ptr [esp + 0x70]

        $sequence_7 = { 64892500000000 83ec10 8a45f3 53 8bd9 56 57 }
            // n = 7, score = 100
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   83ec10               | sub                 esp, 0x10
            //   8a45f3               | mov                 al, byte ptr [ebp - 0xd]
            //   53                   | push                ebx
            //   8bd9                 | mov                 ebx, ecx
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_8 = { 50 c645fc04 e8???????? 83ec10 8d5508 8bcc 89a554ffffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   e8????????           |                     
            //   83ec10               | sub                 esp, 0x10
            //   8d5508               | lea                 edx, [ebp + 8]
            //   8bcc                 | mov                 ecx, esp
            //   89a554ffffff         | mov                 dword ptr [ebp - 0xac], esp

        $sequence_9 = { b90f000000 33c0 8d7c2410 c784246c06000000000000 }
            // n = 4, score = 100
            //   b90f000000           | mov                 ecx, 0xf
            //   33c0                 | xor                 eax, eax
            //   8d7c2410             | lea                 edi, [esp + 0x10]
            //   c784246c06000000000000     | mov    dword ptr [esp + 0x66c], 0

    condition:
        7 of them and filesize < 163840
}