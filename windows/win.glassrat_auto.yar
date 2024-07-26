rule win_glassrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.glassrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glassrat"
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
        $sequence_0 = { 6a00 83ec10 8b4c242c 8bc4 8938 895804 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   83ec10               | sub                 esp, 0x10
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]
            //   8bc4                 | mov                 eax, esp
            //   8938                 | mov                 dword ptr [eax], edi
            //   895804               | mov                 dword ptr [eax + 4], ebx

        $sequence_1 = { 66ab 8d8c24cc040000 51 8bce aa }
            // n = 5, score = 200
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8d8c24cc040000       | lea                 ecx, [esp + 0x4cc]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_2 = { 57 b902010000 83ec10 ba8c020000 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   b902010000           | mov                 ecx, 0x102
            //   83ec10               | sub                 esp, 0x10
            //   ba8c020000           | mov                 edx, 0x28c

        $sequence_3 = { 68007f0000 53 89442438 ff15???????? 53 89442438 }
            // n = 6, score = 200
            //   68007f0000           | push                0x7f00
            //   53                   | push                ebx
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   89442438             | mov                 dword ptr [esp + 0x38], eax

        $sequence_4 = { 8b4a14 8b5218 51 52 }
            // n = 4, score = 200
            //   8b4a14               | mov                 ecx, dword ptr [edx + 0x14]
            //   8b5218               | mov                 edx, dword ptr [edx + 0x18]
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_5 = { 6a00 51 ff15???????? 8b562c 6a00 52 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b562c               | mov                 edx, dword ptr [esi + 0x2c]
            //   6a00                 | push                0
            //   52                   | push                edx

        $sequence_6 = { 76cd b900080000 33c0 8dbdd8dfffff f3ab }
            // n = 5, score = 200
            //   76cd                 | jbe                 0xffffffcf
            //   b900080000           | mov                 ecx, 0x800
            //   33c0                 | xor                 eax, eax
            //   8dbdd8dfffff         | lea                 edi, [ebp - 0x2028]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_7 = { ba12020000 33ff 895304 894308 897b0c e8???????? }
            // n = 6, score = 200
            //   ba12020000           | mov                 edx, 0x212
            //   33ff                 | xor                 edi, edi
            //   895304               | mov                 dword ptr [ebx + 4], edx
            //   894308               | mov                 dword ptr [ebx + 8], eax
            //   897b0c               | mov                 dword ptr [ebx + 0xc], edi
            //   e8????????           |                     

        $sequence_8 = { 8b5e28 8d442410 50 53 ffd7 85c0 7403 }
            // n = 7, score = 200
            //   8b5e28               | mov                 ebx, dword ptr [esi + 0x28]
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_9 = { 40 ebeb 3bc1 751c 83f940 7317 }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   ebeb                 | jmp                 0xffffffed
            //   3bc1                 | cmp                 eax, ecx
            //   751c                 | jne                 0x1e
            //   83f940               | cmp                 ecx, 0x40
            //   7317                 | jae                 0x19

    condition:
        7 of them and filesize < 81920
}