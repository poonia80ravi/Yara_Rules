rule win_soundbite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.soundbite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soundbite"
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
        $sequence_0 = { 8d642400 800080 40 803800 75f7 6a04 }
            // n = 6, score = 100
            //   8d642400             | lea                 esp, [esp]
            //   800080               | add                 byte ptr [eax], 0x80
            //   40                   | inc                 eax
            //   803800               | cmp                 byte ptr [eax], 0
            //   75f7                 | jne                 0xfffffff9
            //   6a04                 | push                4

        $sequence_1 = { 03c2 8985f0fcffff 3bdf 757c 8bcb 2bce b893244992 }
            // n = 7, score = 100
            //   03c2                 | add                 eax, edx
            //   8985f0fcffff         | mov                 dword ptr [ebp - 0x310], eax
            //   3bdf                 | cmp                 ebx, edi
            //   757c                 | jne                 0x7e
            //   8bcb                 | mov                 ecx, ebx
            //   2bce                 | sub                 ecx, esi
            //   b893244992           | mov                 eax, 0x92492493

        $sequence_2 = { 8d55f0 52 8b5508 8d45ac 50 51 }
            // n = 6, score = 100
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8d45ac               | lea                 eax, [ebp - 0x54]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_3 = { 752e 807c241300 750d 8b4d14 8d5301 c644241301 }
            // n = 6, score = 100
            //   752e                 | jne                 0x30
            //   807c241300           | cmp                 byte ptr [esp + 0x13], 0
            //   750d                 | jne                 0xf
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8d5301               | lea                 edx, [ebx + 1]
            //   c644241301           | mov                 byte ptr [esp + 0x13], 1

        $sequence_4 = { 51 52 50 8b4604 57 e8???????? 83c410 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_5 = { 89580c 8b551c 8965ec 56 895010 e8???????? 83c42c }
            // n = 7, score = 100
            //   89580c               | mov                 dword ptr [eax + 0xc], ebx
            //   8b551c               | mov                 edx, dword ptr [ebp + 0x1c]
            //   8965ec               | mov                 dword ptr [ebp - 0x14], esp
            //   56                   | push                esi
            //   895010               | mov                 dword ptr [eax + 0x10], edx
            //   e8????????           |                     
            //   83c42c               | add                 esp, 0x2c

        $sequence_6 = { 8b4590 8b4df4 64890d00000000 59 5f 5e 8b4df0 }
            // n = 7, score = 100
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_7 = { 8bf3 85f6 7e2f b800080000 81fe00080000 7f02 }
            // n = 6, score = 100
            //   8bf3                 | mov                 esi, ebx
            //   85f6                 | test                esi, esi
            //   7e2f                 | jle                 0x31
            //   b800080000           | mov                 eax, 0x800
            //   81fe00080000         | cmp                 esi, 0x800
            //   7f02                 | jg                  4

        $sequence_8 = { 85c0 0f84ce010000 e8???????? 85c0 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   0f84ce010000         | je                  0x1d4
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8b5584 8b4580 52 50 8d4de8 51 8d5580 }
            // n = 7, score = 100
            //   8b5584               | mov                 edx, dword ptr [ebp - 0x7c]
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   51                   | push                ecx
            //   8d5580               | lea                 edx, [ebp - 0x80]

    condition:
        7 of them and filesize < 409600
}