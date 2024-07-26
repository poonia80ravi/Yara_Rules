rule win_ruckguv_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.ruckguv."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ruckguv"
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
        $sequence_0 = { 59 6a10 8d4d2c 51 }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   6a10                 | push                0x10
            //   8d4d2c               | lea                 ecx, [ebp + 0x2c]
            //   51                   | push                ecx

        $sequence_1 = { e8???????? 59 59 894560 3bc7 0f876affffff }
            // n = 6, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   894560               | mov                 dword ptr [ebp + 0x60], eax
            //   3bc7                 | cmp                 eax, edi
            //   0f876affffff         | ja                  0xffffff70

        $sequence_2 = { 8b4834 3bf1 7504 b001 }
            // n = 4, score = 200
            //   8b4834               | mov                 ecx, dword ptr [eax + 0x34]
            //   3bf1                 | cmp                 esi, ecx
            //   7504                 | jne                 6
            //   b001                 | mov                 al, 1

        $sequence_3 = { ff7510 e8???????? 83c418 c9 c3 680cfb1473 6a06 }
            // n = 7, score = 200
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c9                   | leave               
            //   c3                   | ret                 
            //   680cfb1473           | push                0x7314fb0c
            //   6a06                 | push                6

        $sequence_4 = { c9 c3 680cfb1473 6a06 }
            // n = 4, score = 200
            //   c9                   | leave               
            //   c3                   | ret                 
            //   680cfb1473           | push                0x7314fb0c
            //   6a06                 | push                6

        $sequence_5 = { 83ec30 53 56 8b7508 33db 57 85f6 }
            // n = 7, score = 200
            //   83ec30               | sub                 esp, 0x30
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33db                 | xor                 ebx, ebx
            //   57                   | push                edi
            //   85f6                 | test                esi, esi

        $sequence_6 = { 750f 8b470c 03c3 50 e8???????? }
            // n = 5, score = 200
            //   750f                 | jne                 0x11
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   03c3                 | add                 eax, ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { 8d4d48 51 ffd0 683adc703d 6a02 e8???????? }
            // n = 6, score = 200
            //   8d4d48               | lea                 ecx, [ebp + 0x48]
            //   51                   | push                ecx
            //   ffd0                 | call                eax
            //   683adc703d           | push                0x3d70dc3a
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_8 = { 894508 8b4508 0345fc 6a00 6a01 ff75fc }
            // n = 6, score = 200
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_9 = { ff742404 ffd0 c3 6831f478b7 6a02 e8???????? 59 }
            // n = 7, score = 200
            //   ff742404             | push                dword ptr [esp + 4]
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   6831f478b7           | push                0xb778f431
            //   6a02                 | push                2
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 41024
}