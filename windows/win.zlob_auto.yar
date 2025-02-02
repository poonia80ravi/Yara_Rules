rule win_zlob_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.zlob."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zlob"
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
        $sequence_0 = { ff15???????? 83c40c ffd3 ffd3 ffd6 ffd7 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   ffd3                 | call                ebx
            //   ffd3                 | call                ebx
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi

        $sequence_1 = { ff750c ff15???????? 83f8ff 8945fc 0f84e7000000 ffd3 ffd3 }
            // n = 7, score = 200
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   0f84e7000000         | je                  0xed
            //   ffd3                 | call                ebx
            //   ffd3                 | call                ebx

        $sequence_2 = { 50 ffb424bc180000 ff742424 ff742430 e8???????? 83c41c ffd3 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffb424bc180000       | push                dword ptr [esp + 0x18bc]
            //   ff742424             | push                dword ptr [esp + 0x24]
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   ffd3                 | call                ebx

        $sequence_3 = { ffd6 ffd7 ffd6 ffd6 ffd7 33ed be10010000 }
            // n = 7, score = 200
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi
            //   ffd6                 | call                esi
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi
            //   33ed                 | xor                 ebp, ebp
            //   be10010000           | mov                 esi, 0x110

        $sequence_4 = { 5b 59 c20400 8b410c c3 8b442404 }
            // n = 6, score = 200
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   c20400               | ret                 4
            //   8b410c               | mov                 eax, dword ptr [ecx + 0xc]
            //   c3                   | ret                 
            //   8b442404             | mov                 eax, dword ptr [esp + 4]

        $sequence_5 = { ffd6 ffd7 ffd6 ffd6 ffd7 ff7504 6a00 }
            // n = 7, score = 200
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi
            //   ffd6                 | call                esi
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi
            //   ff7504               | push                dword ptr [ebp + 4]
            //   6a00                 | push                0

        $sequence_6 = { 5f f7ff 5f 85d2 7407 6a04 }
            // n = 6, score = 200
            //   5f                   | pop                 edi
            //   f7ff                 | idiv                edi
            //   5f                   | pop                 edi
            //   85d2                 | test                edx, edx
            //   7407                 | je                  9
            //   6a04                 | push                4

        $sequence_7 = { 8d4c2440 51 50 894514 e8???????? 83c424 6a00 }
            // n = 7, score = 200
            //   8d4c2440             | lea                 ecx, [esp + 0x40]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   894514               | mov                 dword ptr [ebp + 0x14], eax
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   6a00                 | push                0

        $sequence_8 = { ff35???????? ff15???????? 8d84243c010000 68???????? }
            // n = 4, score = 200
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8d84243c010000       | lea                 eax, [esp + 0x13c]
            //   68????????           |                     

        $sequence_9 = { ffd7 ffd6 ffd7 ffd6 ffd6 ffd7 838d08010000ff }
            // n = 7, score = 200
            //   ffd7                 | call                edi
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi
            //   ffd6                 | call                esi
            //   ffd6                 | call                esi
            //   ffd7                 | call                edi
            //   838d08010000ff       | or                  dword ptr [ebp + 0x108], 0xffffffff

    condition:
        7 of them and filesize < 98304
}