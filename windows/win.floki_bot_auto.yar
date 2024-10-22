rule win_floki_bot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.floki_bot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.floki_bot"
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
        $sequence_0 = { 8bf0 ff15???????? 8bd8 53 56 ff74242c ff15???????? }
            // n = 7, score = 1100
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   ff15????????         |                     

        $sequence_1 = { 8d543bff e8???????? 56 57 ff7508 c6443eff00 }
            // n = 6, score = 1100
            //   8d543bff             | lea                 edx, [ebx + edi - 1]
            //   e8????????           |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0

        $sequence_2 = { e8???????? 8b471c 8b4f14 01481c 8bc1 01472c 8b472c }
            // n = 7, score = 1100
            //   e8????????           |                     
            //   8b471c               | mov                 eax, dword ptr [edi + 0x1c]
            //   8b4f14               | mov                 ecx, dword ptr [edi + 0x14]
            //   01481c               | add                 dword ptr [eax + 0x1c], ecx
            //   8bc1                 | mov                 eax, ecx
            //   01472c               | add                 dword ptr [edi + 0x2c], eax
            //   8b472c               | mov                 eax, dword ptr [edi + 0x2c]

        $sequence_3 = { 51 e8???????? 01430c 8b430c 8b4b08 8b7d10 c6040800 }
            // n = 7, score = 1100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   01430c               | add                 dword ptr [ebx + 0xc], eax
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]
            //   8b4b08               | mov                 ecx, dword ptr [ebx + 8]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   c6040800             | mov                 byte ptr [eax + ecx], 0

        $sequence_4 = { 58 8955f8 8bf9 e8???????? 57 8d8594fcffff 50 }
            // n = 7, score = 1100
            //   58                   | pop                 eax
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8bf9                 | mov                 edi, ecx
            //   e8????????           |                     
            //   57                   | push                edi
            //   8d8594fcffff         | lea                 eax, [ebp - 0x36c]
            //   50                   | push                eax

        $sequence_5 = { 7511 ff750c ff7508 ff15???????? e9???????? 53 6a1c }
            // n = 7, score = 1100
            //   7511                 | jne                 0x13
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   e9????????           |                     
            //   53                   | push                ebx
            //   6a1c                 | push                0x1c

        $sequence_6 = { 68???????? 8d45f8 e8???????? 8d85a4fdffff 50 ff75f8 ff15???????? }
            // n = 7, score = 1100
            //   68????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   e8????????           |                     
            //   8d85a4fdffff         | lea                 eax, [ebp - 0x25c]
            //   50                   | push                eax
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_7 = { 7452 c645fb00 eb4c 8b7de4 e8???????? 8bf0 83feff }
            // n = 7, score = 1100
            //   7452                 | je                  0x54
            //   c645fb00             | mov                 byte ptr [ebp - 5], 0
            //   eb4c                 | jmp                 0x4e
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1

        $sequence_8 = { 53 56 68???????? 33db ff15???????? 8bf0 3bf3 }
            // n = 7, score = 1100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   68????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   3bf3                 | cmp                 esi, ebx

        $sequence_9 = { 0fb6441de4 50 68???????? 8d75f4 e8???????? 59 }
            // n = 6, score = 1100
            //   0fb6441de4           | movzx               eax, byte ptr [ebp + ebx - 0x1c]
            //   50                   | push                eax
            //   68????????           |                     
            //   8d75f4               | lea                 esi, [ebp - 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 286720
}