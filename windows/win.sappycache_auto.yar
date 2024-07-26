rule win_sappycache_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sappycache."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sappycache"
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
        $sequence_0 = { 488d0533980000 488bd9 488901 f6c201 740a ba18000000 e8???????? }
            // n = 7, score = 200
            //   488d0533980000       | dec                 esp
            //   488bd9               | lea                 eax, [esp + 0x40]
            //   488901               | mov                 ecx, edx
            //   f6c201               | dec                 eax
            //   740a                 | lea                 edx, [esp + 0x48]
            //   ba18000000           | dec                 eax
            //   e8????????           |                     

        $sequence_1 = { e8???????? 33c0 b900000200 488bfb f3aa }
            // n = 5, score = 200
            //   e8????????           |                     
            //   33c0                 | sub                 esp, eax
            //   b900000200           | dec                 eax
            //   488bfb               | lea                 esi, [ebx + 0x128]
            //   f3aa                 | mov                 ebp, 6

        $sequence_2 = { e9???????? 488d1d612c0100 41b804010000 488bd3 }
            // n = 4, score = 200
            //   e9????????           |                     
            //   488d1d612c0100       | mov                 ecx, ebx
            //   41b804010000         | dec                 ecx
            //   488bd3               | xchg                dword ptr [edi + esi*8 + 0x18620], eax

        $sequence_3 = { e9???????? 488d156ba20000 488d0d54a20000 e8???????? c705????????02000000 }
            // n = 5, score = 200
            //   e9????????           |                     
            //   488d156ba20000       | test                eax, eax
            //   488d0d54a20000       | dec                 esp
            //   e8????????           |                     
            //   c705????????02000000     |     

        $sequence_4 = { 7556 e8???????? e8???????? 85c0 740c 488d0d91050000 e8???????? }
            // n = 7, score = 200
            //   7556                 | xor                 eax, eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   85c0                 | jne                 0x8a
            //   740c                 | dec                 eax
            //   488d0d91050000       | lea                 eax, [0x10777]
            //   e8????????           |                     

        $sequence_5 = { 488d1593200100 488d4c2420 e8???????? cc 4883790800 488d05a4990000 }
            // n = 6, score = 200
            //   488d1593200100       | xor                 ecx, esp
            //   488d4c2420           | dec                 eax
            //   e8????????           |                     
            //   cc                   | add                 esp, 0x6348
            //   4883790800           | inc                 ecx
            //   488d05a4990000       | pop                 ebp

        $sequence_6 = { 3b15???????? 7350 488bca 4c8d05f9ca0000 83e13f 488bc2 48c1f806 }
            // n = 7, score = 200
            //   3b15????????         |                     
            //   7350                 | lea                 ecx, [0x122c3]
            //   488bca               | jmp                 0x780
            //   4c8d05f9ca0000       | vmulsd              xmm1, xmm1, qword ptr [ecx + eax*8]
            //   83e13f               | dec                 esp
            //   488bc2               | lea                 ecx, [0x76a5]
            //   48c1f806             | vmulsd              xmm0, xmm1, xmm1

        $sequence_7 = { 488d05e3070100 eb04 4883c024 8938 e8???????? 488d1dcb070100 4885c0 }
            // n = 7, score = 200
            //   488d05e3070100       | lea                 ecx, [0x130bc]
            //   eb04                 | dec                 ebp
            //   4883c024             | test                edx, edx
            //   8938                 | je                  0x895
            //   e8????????           |                     
            //   488d1dcb070100       | bt                  eax, 0x19
            //   4885c0               | jae                 0x84d

        $sequence_8 = { 4c8ba42440630000 85ff 0f84d1fcffff 418bfd 44896d80 498bdd }
            // n = 6, score = 200
            //   4c8ba42440630000     | lea                 eax, [0x16270]
            //   85ff                 | mov                 ecx, 0x28
            //   0f84d1fcffff         | dec                 eax
            //   418bfd               | lea                 eax, [eax + 0x80]
            //   44896d80             | movups              xmm0, xmmword ptr [ebx]
            //   498bdd               | dec                 eax

        $sequence_9 = { 488bd5 33c9 ff15???????? 488bf0 4885c0 7510 8d480e }
            // n = 7, score = 200
            //   488bd5               | dec                 eax
            //   33c9                 | lea                 ecx, [ebp + 0x1220]
            //   ff15????????         |                     
            //   488bf0               | inc                 ecx
            //   4885c0               | mov                 eax, 0x1000
            //   7510                 | inc                 ecx
            //   8d480e               | mov                 eax, 0x800

    condition:
        7 of them and filesize < 262144
}