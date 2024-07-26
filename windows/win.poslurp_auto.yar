rule win_poslurp_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.poslurp."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poslurp"
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
        $sequence_0 = { 4889442420 ff15???????? 488b7c2468 85c0 }
            // n = 4, score = 100
            //   4889442420           | mov                 dword ptr [esp + 0x48], eax
            //   ff15????????         |                     
            //   488b7c2468           | dec                 eax
            //   85c0                 | lea                 eax, [esp + 0xa0]

        $sequence_1 = { 33d2 ff15???????? 4c8bb42490000000 33db 4983c402 e9???????? 4c8bed }
            // n = 7, score = 100
            //   33d2                 | movzx               eax, word ptr [edx]
            //   ff15????????         |                     
            //   4c8bb42490000000     | dec                 ecx
            //   33db                 | dec                 eax
            //   4983c402             | sar                 ecx, 1
            //   e9????????           |                     
            //   4c8bed               | mov                 edi, ebx

        $sequence_2 = { 740e 0fb7d0 488bcd 41ffd5 488907 eb0e }
            // n = 6, score = 100
            //   740e                 | dec                 ecx
            //   0fb7d0               | mov                 ecx, ecx
            //   488bcd               | inc                 ebp
            //   41ffd5               | xor                 eax, eax
            //   488907               | xor                 edx, edx
            //   eb0e                 | jae                 0x3d7

        $sequence_3 = { b910000000 f3a4 488d4d01 488d542420 c644243000 e8???????? 4885c0 }
            // n = 7, score = 100
            //   b910000000           | cmp                 ecx, edi
            //   f3a4                 | je                  0xae
            //   488d4d01             | inc                 ecx
            //   488d542420           | inc                 ecx
            //   c644243000           | xor                 ecx, ecx
            //   e8????????           |                     
            //   4885c0               | inc                 ecx

        $sequence_4 = { 488d15a9100000 41b93f000f00 4533c0 48c7c102000080 }
            // n = 4, score = 100
            //   488d15a9100000       | ret                 
            //   41b93f000f00         | dec                 eax
            //   4533c0               | lea                 edx, [0x16e1]
            //   48c7c102000080       | dec                 eax

        $sequence_5 = { 85d2 747f 4c8bd9 4c8d0411 4c2b5c0830 7471 418b4004 }
            // n = 7, score = 100
            //   85d2                 | sub                 esi, eax
            //   747f                 | je                  0x3d1
            //   4c8bd9               | movzx               eax, word ptr [ebp]
            //   4c8d0411             | dec                 ecx
            //   4c2b5c0830           | sub                 eax, 0x30
            //   7471                 | cmp                 eax, 9
            //   418b4004             | ja                  0x35a

        $sequence_6 = { 4885c0 0f8412010000 488bc8 482bcd 48d1f9 }
            // n = 5, score = 100
            //   4885c0               | or                  ecx, 0xffffffff
            //   0f8412010000         | inc                 ecx
            //   488bc8               | mov                 eax, edx
            //   482bcd               | dec                 esp
            //   48d1f9               | mov                 dword ptr [esp + 0x148], ebp

        $sequence_7 = { 4c8d4c2458 448bc5 488bd6 488bcb 48897c2420 ff15???????? 488bcb }
            // n = 7, score = 100
            //   4c8d4c2458           | mov                 edx, 0x40000000
            //   448bc5               | mov                 dword ptr [esp + 0x28], 2
            //   488bd6               | mov                 dword ptr [esp + 0x20], 4
            //   488bcb               | dec                 eax
            //   48897c2420           | cmp                 eax, -1
            //   ff15????????         |                     
            //   488bcb               | je                  0x1c2d

        $sequence_8 = { 7709 ffc1 49ffc4 85d2 }
            // n = 4, score = 100
            //   7709                 | lea                 ecx, [esp + 0x30]
            //   ffc1                 | dec                 eax
            //   49ffc4               | mov                 dword ptr [esp + 0x30], ebx
            //   85d2                 | dec                 eax

        $sequence_9 = { ffce 488bd5 48d1f9 8bfb 85c9 }
            // n = 5, score = 100
            //   ffce                 | dec                 eax
            //   488bd5               | arpl                word ptr [ecx + 0x3c], ax
            //   48d1f9               | inc                 ebp
            //   8bfb                 | xor                 edi, edi
            //   85c9                 | dec                 ecx

    condition:
        7 of them and filesize < 50176
}