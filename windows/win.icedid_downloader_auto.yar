rule win_icedid_downloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.icedid_downloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid_downloader"
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
        $sequence_0 = { 8d8574fdffff 8955dc 50 ff15???????? 8be5 5d c3 }
            // n = 7, score = 400
            //   8d8574fdffff         | lea                 eax, [ebp - 0x28c]
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_1 = { 56 be1c010000 8d85e4feffff 56 6a00 }
            // n = 5, score = 400
            //   56                   | push                esi
            //   be1c010000           | mov                 esi, 0x11c
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   56                   | push                esi
            //   6a00                 | push                0

        $sequence_2 = { 59 50 ffd3 8b4c2418 8bf8 }
            // n = 5, score = 400
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   8bf8                 | mov                 edi, eax

        $sequence_3 = { 5e 33ff 894568 56 }
            // n = 4, score = 400
            //   5e                   | pop                 esi
            //   33ff                 | xor                 edi, edi
            //   894568               | mov                 dword ptr [ebp + 0x68], eax
            //   56                   | push                esi

        $sequence_4 = { 7444 53 8d45c4 50 68???????? }
            // n = 5, score = 400
            //   7444                 | je                  0x46
            //   53                   | push                ebx
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_5 = { 47 4e 803f00 75f9 53 47 }
            // n = 6, score = 400
            //   47                   | inc                 edi
            //   4e                   | dec                 esi
            //   803f00               | cmp                 byte ptr [edi], 0
            //   75f9                 | jne                 0xfffffffb
            //   53                   | push                ebx
            //   47                   | inc                 edi

        $sequence_6 = { 8d442428 50 ff742438 ff15???????? 8d442440 50 68???????? }
            // n = 7, score = 400
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   ff742438             | push                dword ptr [esp + 0x38]
            //   ff15????????         |                     
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_7 = { 8b85e8feffff 8b7508 83f806 7212 e8???????? 85c0 8b85e8feffff }
            // n = 7, score = 400
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   83f806               | cmp                 eax, 6
            //   7212                 | jb                  0x14
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]

        $sequence_8 = { 83ec3c 56 57 683f000f00 }
            // n = 4, score = 400
            //   83ec3c               | sub                 esp, 0x3c
            //   56                   | push                esi
            //   57                   | push                edi
            //   683f000f00           | push                0xf003f

        $sequence_9 = { 55 55 55 55 55 57 51 }
            // n = 7, score = 400
            //   55                   | push                ebp
            //   55                   | push                ebp
            //   55                   | push                ebp
            //   55                   | push                ebp
            //   55                   | push                ebp
            //   57                   | push                edi
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 40960
}