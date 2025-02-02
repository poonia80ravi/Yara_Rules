rule win_gearshift_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.gearshift."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gearshift"
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
        $sequence_0 = { 48894c2430 4885c9 741c f0ff09 7517 488d0523350300 488b4c2430 }
            // n = 7, score = 200
            //   48894c2430           | push                0
            //   4885c9               | push                0x10001eec
            //   741c                 | push                dword ptr [ebp + 8]
            //   f0ff09               | push                edi
            //   7517                 | push                0
            //   488d0523350300       | push                0
            //   488b4c2430           | push                0x10002b43

        $sequence_1 = { 488bcb ff9600010000 33c0 4881c490000000 }
            // n = 4, score = 200
            //   488bcb               | mov                 dword ptr [edx + 0x10], eax
            //   ff9600010000         | dec                 eax
            //   33c0                 | lea                 eax, [edx + 0xffc0]
            //   4881c490000000       | dec                 eax

        $sequence_2 = { 41b940000000 41b800100000 4c896008 4c897810 4c897818 418b5550 498bcc }
            // n = 7, score = 200
            //   41b940000000         | jae                 0x1618
            //   41b800100000         | dec                 eax
            //   4c896008             | sub                 edi, ecx
            //   4c897810             | mov                 dl, 0xcc
            //   4c897818             | dec                 esp
            //   418b5550             | mov                 eax, edi
            //   498bcc               | dec                 eax

        $sequence_3 = { 8bc8 ff15???????? 33c0 488d542438 488d0d60bf0000 }
            // n = 5, score = 200
            //   8bc8                 | dec                 eax
            //   ff15????????         |                     
            //   33c0                 | mov                 dword ptr [esp + 0x70], eax
            //   488d542438           | dec                 eax
            //   488d0d60bf0000       | mov                 ecx, dword ptr [esp + 0x70]

        $sequence_4 = { 498bc8 4c8d151d330300 498bc0 48c1f805 83e11f 498b04c2 }
            // n = 6, score = 200
            //   498bc8               | dec                 ecx
            //   4c8d151d330300       | mov                 ebx, esp
            //   498bc0               | dec                 eax
            //   48c1f805             | mov                 ebp, eax
            //   83e11f               | dec                 esp
            //   498b04c2             | mov                 dword ptr [esp + 0x30], ebp

        $sequence_5 = { 8bd9 488d0dd56e0000 ff15???????? 4885c0 7419 }
            // n = 5, score = 200
            //   8bd9                 | dec                 eax
            //   488d0dd56e0000       | mov                 ecx, dword ptr [ebp + 0xbe0]
            //   ff15????????         |                     
            //   4885c0               | dec                 eax
            //   7419                 | xor                 ecx, esp

        $sequence_6 = { 8905???????? 8bd7 4c8d056880ffff 89542420 }
            // n = 4, score = 200
            //   8905????????         |                     
            //   8bd7                 | dec                 eax
            //   4c8d056880ffff       | lea                 edx, [0xb027]
            //   89542420             | dec                 eax

        $sequence_7 = { 4881c4d8000000 c3 85c0 0f8514010000 c705????????10000000 b810000000 488b8c24c0000000 }
            // n = 7, score = 200
            //   4881c4d8000000       | and                 ecx, 0x1f
            //   c3                   | dec                 eax
            //   85c0                 | sar                 eax, 5
            //   0f8514010000         | dec                 eax
            //   c705????????10000000     |     
            //   b810000000           | imul                ecx, ecx, 0x58
            //   488b8c24c0000000     | dec                 eax

        $sequence_8 = { 488bc1 4c8d9c24c0000000 498b5b20 498b7328 }
            // n = 4, score = 200
            //   488bc1               | dec                 eax
            //   4c8d9c24c0000000     | lea                 eax, [0xfc87]
            //   498b5b20             | jmp                 0x487
            //   498b7328             | dec                 eax

        $sequence_9 = { 498d0c51 448b548c38 410fbae01a 7305 410fbaea09 }
            // n = 5, score = 200
            //   498d0c51             | jb                  0x452
            //   448b548c38           | dec                 eax
            //   410fbae01a           | lea                 eax, [0x30c08]
            //   7305                 | dec                 eax
            //   410fbaea09           | cmp                 ebx, eax

    condition:
        7 of them and filesize < 540672
}