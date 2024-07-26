rule win_spora_ransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.spora_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spora_ransom"
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
        $sequence_0 = { ff15???????? 85c0 7466 56 57 bf00020000 57 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7466                 | je                  0x68
            //   56                   | push                esi
            //   57                   | push                edi
            //   bf00020000           | mov                 edi, 0x200
            //   57                   | push                edi

        $sequence_1 = { 8bec 83ec10 53 56 ff15???????? 8bd8 33f6 }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   53                   | push                ebx
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   33f6                 | xor                 esi, esi

        $sequence_2 = { 50 68???????? 57 e8???????? 85c0 740e 8b45fc }
            // n = 7, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_3 = { 57 ff15???????? 57 e8???????? 57 ff15???????? 83c620 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   83c620               | add                 esi, 0x20

        $sequence_4 = { 56 6a19 ff75f8 ff15???????? 85c0 7425 837dfc00 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   6a19                 | push                0x19
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7425                 | je                  0x27
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0

        $sequence_5 = { ff15???????? 8bf8 3bfe 7438 57 53 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   3bfe                 | cmp                 edi, esi
            //   7438                 | je                  0x3a
            //   57                   | push                edi
            //   53                   | push                ebx

        $sequence_6 = { ff742404 e8???????? c21000 55 8bec 83ec0c }
            // n = 6, score = 200
            //   ff742404             | push                dword ptr [esp + 4]
            //   e8????????           |                     
            //   c21000               | ret                 0x10
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc

        $sequence_7 = { 56 ff7508 e8???????? 85c0 7422 56 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   56                   | push                esi

        $sequence_8 = { 0f85a1000000 53 8b1d???????? 56 57 be00400000 }
            // n = 6, score = 200
            //   0f85a1000000         | jne                 0xa7
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   be00400000           | mov                 esi, 0x4000

        $sequence_9 = { ff4d08 75b4 8b7df4 57 ff15???????? ff75fc }
            // n = 6, score = 200
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   75b4                 | jne                 0xffffffb6
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 73728
}