rule win_classfon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.classfon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.classfon"
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
        $sequence_0 = { 40 8bf8 803f00 75dc }
            // n = 4, score = 200
            //   40                   | inc                 eax
            //   8bf8                 | mov                 edi, eax
            //   803f00               | cmp                 byte ptr [edi], 0
            //   75dc                 | jne                 0xffffffde

        $sequence_1 = { 53 68???????? 51 c744242802000000 c744242c2c010000 ff15???????? }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   68????????           |                     
            //   51                   | push                ecx
            //   c744242802000000     | mov                 dword ptr [esp + 0x28], 2
            //   c744242c2c010000     | mov                 dword ptr [esp + 0x2c], 0x12c
            //   ff15????????         |                     

        $sequence_2 = { 6800000080 57 ff15???????? 8b742418 83f8ff 898600020000 }
            // n = 6, score = 200
            //   6800000080           | push                0x80000000
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]
            //   83f8ff               | cmp                 eax, -1
            //   898600020000         | mov                 dword ptr [esi + 0x200], eax

        $sequence_3 = { 83ec08 8b54240c 8b442418 8d4c2400 }
            // n = 4, score = 200
            //   83ec08               | sub                 esp, 8
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8d4c2400             | lea                 ecx, [esp]

        $sequence_4 = { 8b542418 f2ae f7d1 51 8d4c2428 51 }
            // n = 6, score = 200
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   51                   | push                ecx
            //   8d4c2428             | lea                 ecx, [esp + 0x28]
            //   51                   | push                ecx

        $sequence_5 = { f3ab 66ab 6804010000 8d4c241c 68???????? 51 c744241802000080 }
            // n = 7, score = 200
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   6804010000           | push                0x104
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   68????????           |                     
            //   51                   | push                ecx
            //   c744241802000080     | mov                 dword ptr [esp + 0x18], 0x80000002

        $sequence_6 = { 51 ff15???????? 33db a3???????? 3bc3 0f84e5010000 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   33db                 | xor                 ebx, ebx
            //   a3????????           |                     
            //   3bc3                 | cmp                 eax, ebx
            //   0f84e5010000         | je                  0x1eb

        $sequence_7 = { 740d 50 ff15???????? 89be08020000 8b8604020000 8b1d???????? 3bc7 }
            // n = 7, score = 200
            //   740d                 | je                  0xf
            //   50                   | push                eax
            //   ff15????????         |                     
            //   89be08020000         | mov                 dword ptr [esi + 0x208], edi
            //   8b8604020000         | mov                 eax, dword ptr [esi + 0x204]
            //   8b1d????????         |                     
            //   3bc7                 | cmp                 eax, edi

        $sequence_8 = { c744240000000000 51 68???????? 52 c744241001000000 89442424 }
            // n = 6, score = 200
            //   c744240000000000     | mov                 dword ptr [esp], 0
            //   51                   | push                ecx
            //   68????????           |                     
            //   52                   | push                edx
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1
            //   89442424             | mov                 dword ptr [esp + 0x24], eax

        $sequence_9 = { 81c418020000 c3 5f 5e 33c0 }
            // n = 5, score = 200
            //   81c418020000         | add                 esp, 0x218
            //   c3                   | ret                 
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 73728
}