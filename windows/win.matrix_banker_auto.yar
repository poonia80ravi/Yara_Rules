rule win_matrix_banker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.matrix_banker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matrix_banker"
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
        $sequence_0 = { eb16 8d489f 80f905 7704 04a9 eb0a 8d48bf }
            // n = 7, score = 900
            //   eb16                 | mov                 ecx, ebx
            //   8d489f               | jne                 0xf2d
            //   80f905               | call                ebx
            //   7704                 | cmp                 eax, 0x3e5
            //   04a9                 | jne                 0xf42
            //   eb0a                 | push                dword ptr [ebp - 0x10]
            //   8d48bf               | push                dword ptr [esi + 0x38]

        $sequence_1 = { 80f905 7704 04a9 eb0a 8d48bf 80f905 }
            // n = 6, score = 900
            //   80f905               | dec                 eax
            //   7704                 | mov                 ecx, dword ptr [edi + 0x18]
            //   04a9                 | dec                 eax
            //   eb0a                 | mov                 dword ptr [esp + 0x38], edi
            //   8d48bf               | xor                 ebx, ebx
            //   80f905               | inc                 ecx

        $sequence_2 = { 8d48bf 80f905 7702 04c9 }
            // n = 4, score = 900
            //   8d48bf               | mov                 eax, dword ptr [edx]
            //   80f905               | mov                 dword ptr [esp + 0x10], eax
            //   7702                 | mov                 eax, dword ptr [edx + 4]
            //   04c9                 | mov                 eax, dword ptr [ebx]

        $sequence_3 = { 8d4a9f 80f905 7705 80c2a9 }
            // n = 4, score = 900
            //   8d4a9f               | mov                 eax, dword ptr [ebx]
            //   80f905               | call                dword ptr [eax + 0x30]
            //   7705                 | mov                 eax, dword ptr [ebx]
            //   80c2a9               | lea                 ecx, [esp + 0x50]

        $sequence_4 = { 7705 80c2a9 eb0b 8d4abf 80f905 7703 80c2c9 }
            // n = 7, score = 900
            //   7705                 | dec                 eax
            //   80c2a9               | mov                 dword ptr [edi + 0x18], 0xf
            //   eb0b                 | dec                 eax
            //   8d4abf               | mov                 dword ptr [ebx + 0x20], ecx
            //   80f905               | dec                 eax
            //   7703                 | mov                 ecx, dword ptr [esi + 8]
            //   80c2c9               | dec                 eax

        $sequence_5 = { 80f905 7702 04c9 8d4ad0 }
            // n = 4, score = 900
            //   80f905               | lea                 eax, [ebp - 0x1c]
            //   7702                 | push                0
            //   04c9                 | push                0
            //   8d4ad0               | push                0

        $sequence_6 = { eb16 8d489f 80f905 7704 04a9 }
            // n = 5, score = 900
            //   eb16                 | xor                 edx, edx
            //   8d489f               | mov                 dword ptr [esp + 0x1c], esi
            //   80f905               | push                eax
            //   7704                 | lea                 eax, [esp + 0x18]
            //   04a9                 | mov                 dword ptr [esp + 0x18], 4

        $sequence_7 = { 80f905 7704 04a9 eb0a 8d48bf 80f905 7702 }
            // n = 7, score = 900
            //   80f905               | dec                 eax
            //   7704                 | mov                 dword ptr [esp + 0x60], ebx
            //   04a9                 | dec                 eax
            //   eb0a                 | mov                 ebx, dword ptr [esp + 0x38]
            //   8d48bf               | dec                 eax
            //   80f905               | mov                 dword ptr [esp + 0x70], edi
            //   7702                 | dec                 esp

        $sequence_8 = { 04a9 eb0a 8d48bf 80f905 }
            // n = 4, score = 900
            //   04a9                 | add                 al, 0x5c
            //   eb0a                 | add                 al, 0x4c
            //   8d48bf               | out                 0xb2, al
            //   80f905               | add                 al, 0x23

        $sequence_9 = { 721e 8125????????fffdffff 8125????????fffdffff 8125????????fffdffff }
            // n = 4, score = 900
            //   721e                 | dec                 esp
            //   8125????????fffdffff     |     
            //   8125????????fffdffff     |     
            //   8125????????fffdffff     |     

    condition:
        7 of them and filesize < 422912
}