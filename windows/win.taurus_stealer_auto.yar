rule win_taurus_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.taurus_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taurus_stealer"
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
        $sequence_0 = { 6a72 8d4dcc 8845d0 e8???????? 6a6f 8d4dcc 8845d1 }
            // n = 7, score = 200
            //   6a72                 | push                0x72
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   8845d0               | mov                 byte ptr [ebp - 0x30], al
            //   e8????????           |                     
            //   6a6f                 | push                0x6f
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   8845d1               | mov                 byte ptr [ebp - 0x2f], al

        $sequence_1 = { 0fbec0 250f000080 7905 48 83c8f0 40 28440d0d }
            // n = 7, score = 200
            //   0fbec0               | movsx               eax, al
            //   250f000080           | and                 eax, 0x8000000f
            //   7905                 | jns                 7
            //   48                   | dec                 eax
            //   83c8f0               | or                  eax, 0xfffffff0
            //   40                   | inc                 eax
            //   28440d0d             | sub                 byte ptr [ebp + ecx + 0xd], al

        $sequence_2 = { 8d4df1 8bd0 51 8d4da4 e8???????? 59 8d4d8c }
            // n = 7, score = 200
            //   8d4df1               | lea                 ecx, [ebp - 0xf]
            //   8bd0                 | mov                 edx, eax
            //   51                   | push                ecx
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d4d8c               | lea                 ecx, [ebp - 0x74]

        $sequence_3 = { 83c608 8b4de0 8b45f4 41 2b45e4 03c8 8975f0 }
            // n = 7, score = 200
            //   83c608               | add                 esi, 8
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   41                   | inc                 ecx
            //   2b45e4               | sub                 eax, dword ptr [ebp - 0x1c]
            //   03c8                 | add                 ecx, eax
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi

        $sequence_4 = { 7305 8a45f3 ebe2 8d45f4 885dfb 50 8d4dd4 }
            // n = 7, score = 200
            //   7305                 | jae                 7
            //   8a45f3               | mov                 al, byte ptr [ebp - 0xd]
            //   ebe2                 | jmp                 0xffffffe4
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   885dfb               | mov                 byte ptr [ebp - 5], bl
            //   50                   | push                eax
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]

        $sequence_5 = { 0fb70458 8b0482 03c1 eb02 33c0 5f 5e }
            // n = 7, score = 200
            //   0fb70458             | movzx               eax, word ptr [eax + ebx*2]
            //   8b0482               | mov                 eax, dword ptr [edx + eax*4]
            //   03c1                 | add                 eax, ecx
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_6 = { 6a0a 8d855cffffff 895dd8 50 895ddc e8???????? 0f2805???????? }
            // n = 7, score = 200
            //   6a0a                 | push                0xa
            //   8d855cffffff         | lea                 eax, [ebp - 0xa4]
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx
            //   50                   | push                eax
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   e8????????           |                     
            //   0f2805????????       |                     

        $sequence_7 = { 8bd9 56 57 ff7508 8903 894304 }
            // n = 6, score = 200
            //   8bd9                 | mov                 ebx, ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8903                 | mov                 dword ptr [ebx], eax
            //   894304               | mov                 dword ptr [ebx + 4], eax

        $sequence_8 = { ebe2 8d45e6 8855f3 50 8d4db8 e8???????? 8d45f4 }
            // n = 7, score = 200
            //   ebe2                 | jmp                 0xffffffe4
            //   8d45e6               | lea                 eax, [ebp - 0x1a]
            //   8855f3               | mov                 byte ptr [ebp - 0xd], dl
            //   50                   | push                eax
            //   8d4db8               | lea                 ecx, [ebp - 0x48]
            //   e8????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_9 = { 75f9 2bce 8d442441 51 50 8bca }
            // n = 6, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   2bce                 | sub                 ecx, esi
            //   8d442441             | lea                 eax, [esp + 0x41]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8bca                 | mov                 ecx, edx

    condition:
        7 of them and filesize < 524288
}