rule win_webc2_greencat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.webc2_greencat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_greencat"
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
        $sequence_0 = { ff15???????? 395dfc 7414 68???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   7414                 | je                  0x16
            //   68????????           |                     

        $sequence_1 = { 0f8478030000 3bc3 0f8470030000 6800020000 e8???????? }
            // n = 5, score = 100
            //   0f8478030000         | je                  0x37e
            //   3bc3                 | cmp                 eax, ebx
            //   0f8470030000         | je                  0x376
            //   6800020000           | push                0x200
            //   e8????????           |                     

        $sequence_2 = { 3818 0f857dfeffff ff750c e8???????? }
            // n = 4, score = 100
            //   3818                 | cmp                 byte ptr [eax], bl
            //   0f857dfeffff         | jne                 0xfffffe83
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     

        $sequence_3 = { c645d3e6 c645d4e8 c645d540 c645d64a c645d7e6 c645d840 }
            // n = 6, score = 100
            //   c645d3e6             | mov                 byte ptr [ebp - 0x2d], 0xe6
            //   c645d4e8             | mov                 byte ptr [ebp - 0x2c], 0xe8
            //   c645d540             | mov                 byte ptr [ebp - 0x2b], 0x40
            //   c645d64a             | mov                 byte ptr [ebp - 0x2a], 0x4a
            //   c645d7e6             | mov                 byte ptr [ebp - 0x29], 0xe6
            //   c645d840             | mov                 byte ptr [ebp - 0x28], 0x40

        $sequence_4 = { 57 3935???????? 750a 68???????? e9???????? ff35???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   3935????????         |                     
            //   750a                 | jne                 0xc
            //   68????????           |                     
            //   e9????????           |                     
            //   ff35????????         |                     

        $sequence_5 = { 7525 807c0a032d 751e 8d77fe 3bc6 7417 803c012d }
            // n = 7, score = 100
            //   7525                 | jne                 0x27
            //   807c0a032d           | cmp                 byte ptr [edx + ecx + 3], 0x2d
            //   751e                 | jne                 0x20
            //   8d77fe               | lea                 esi, [edi - 2]
            //   3bc6                 | cmp                 eax, esi
            //   7417                 | je                  0x19
            //   803c012d             | cmp                 byte ptr [ecx + eax], 0x2d

        $sequence_6 = { 50 6a1f ff760c ff15???????? 85c0 7421 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   6a1f                 | push                0x1f
            //   ff760c               | push                dword ptr [esi + 0xc]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23

        $sequence_7 = { ff750c ff7508 e8???????? 895dfc 8d4dac e8???????? 3bc3 }
            // n = 7, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   e8????????           |                     
            //   3bc3                 | cmp                 eax, ebx

        $sequence_8 = { ff75f8 ff15???????? 85c0 7470 8d45fc 8975fc 50 }
            // n = 7, score = 100
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7470                 | je                  0x72
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   50                   | push                eax

        $sequence_9 = { 03c3 56 50 57 e8???????? ff7508 }
            // n = 6, score = 100
            //   03c3                 | add                 eax, ebx
            //   56                   | push                esi
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 57344
}