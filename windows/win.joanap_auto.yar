rule win_joanap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.joanap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joanap"
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
        $sequence_0 = { e8???????? 83c404 56 ff15???????? 6a00 ff15???????? 83c404 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4

        $sequence_1 = { 64890d00000000 81c410070000 c3 8d942495000000 52 56 }
            // n = 6, score = 100
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   81c410070000         | add                 esp, 0x710
            //   c3                   | ret                 
            //   8d942495000000       | lea                 edx, [esp + 0x95]
            //   52                   | push                edx
            //   56                   | push                esi

        $sequence_2 = { 8b1d???????? 83c404 ffd7 2501000080 7905 }
            // n = 5, score = 100
            //   8b1d????????         |                     
            //   83c404               | add                 esp, 4
            //   ffd7                 | call                edi
            //   2501000080           | and                 eax, 0x80000001
            //   7905                 | jns                 7

        $sequence_3 = { 5f 33c0 5e 81c400010000 c3 5f }
            // n = 6, score = 100
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   81c400010000         | add                 esp, 0x100
            //   c3                   | ret                 
            //   5f                   | pop                 edi

        $sequence_4 = { 8b4c2410 51 ff15???????? 57 ff15???????? 5e 5b }
            // n = 7, score = 100
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_5 = { 83e010 3c10 755c 8d4c2440 8d942454010000 }
            // n = 5, score = 100
            //   83e010               | and                 eax, 0x10
            //   3c10                 | cmp                 al, 0x10
            //   755c                 | jne                 0x5e
            //   8d4c2440             | lea                 ecx, [esp + 0x40]
            //   8d942454010000       | lea                 edx, [esp + 0x154]

        $sequence_6 = { 8d8c2454010000 50 51 e8???????? 83c408 8d942454010000 52 }
            // n = 7, score = 100
            //   8d8c2454010000       | lea                 ecx, [esp + 0x154]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d942454010000       | lea                 edx, [esp + 0x154]
            //   52                   | push                edx

        $sequence_7 = { ff15???????? 3bc6 746e 56 68???????? 68???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   3bc6                 | cmp                 eax, esi
            //   746e                 | je                  0x70
            //   56                   | push                esi
            //   68????????           |                     
            //   68????????           |                     

        $sequence_8 = { 8dbe78030000 8be9 83c9ff 03ea 8d96fc040000 f2ae f7d1 }
            // n = 7, score = 100
            //   8dbe78030000         | lea                 edi, [esi + 0x378]
            //   8be9                 | mov                 ebp, ecx
            //   83c9ff               | or                  ecx, 0xffffffff
            //   03ea                 | add                 ebp, edx
            //   8d96fc040000         | lea                 edx, [esi + 0x4fc]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_9 = { 8b15???????? 668b4224 66894304 8b0d???????? 8b11 895310 a1???????? }
            // n = 7, score = 100
            //   8b15????????         |                     
            //   668b4224             | mov                 ax, word ptr [edx + 0x24]
            //   66894304             | mov                 word ptr [ebx + 4], ax
            //   8b0d????????         |                     
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   895310               | mov                 dword ptr [ebx + 0x10], edx
            //   a1????????           |                     

    condition:
        7 of them and filesize < 270336
}