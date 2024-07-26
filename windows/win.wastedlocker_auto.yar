rule win_wastedlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.wastedlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedlocker"
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
        $sequence_0 = { 57 ff750c ff15???????? 8bf8 8d04bd24000000 }
            // n = 5, score = 1000
            //   57                   | push                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   8d04bd24000000       | lea                 eax, [edi*4 + 0x24]

        $sequence_1 = { 5e 8bc3 2b45f0 5f c60300 5b }
            // n = 6, score = 1000
            //   5e                   | pop                 esi
            //   8bc3                 | mov                 eax, ebx
            //   2b45f0               | sub                 eax, dword ptr [ebp - 0x10]
            //   5f                   | pop                 edi
            //   c60300               | mov                 byte ptr [ebx], 0
            //   5b                   | pop                 ebx

        $sequence_2 = { 8d441b02 50 ff750c 8d447e02 }
            // n = 4, score = 1000
            //   8d441b02             | lea                 eax, [ebx + ebx + 2]
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d447e02             | lea                 eax, [esi + edi*2 + 2]

        $sequence_3 = { c1ea04 33ca c1e804 33048e 85ed 75dd 5e }
            // n = 7, score = 1000
            //   c1ea04               | shr                 edx, 4
            //   33ca                 | xor                 ecx, edx
            //   c1e804               | shr                 eax, 4
            //   33048e               | xor                 eax, dword ptr [esi + ecx*4]
            //   85ed                 | test                ebp, ebp
            //   75dd                 | jne                 0xffffffdf
            //   5e                   | pop                 esi

        $sequence_4 = { 8d45f4 8945e4 8d45dc 50 c745dc18000000 897de0 c745e840000000 }
            // n = 7, score = 1000
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   c745dc18000000       | mov                 dword ptr [ebp - 0x24], 0x18
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   c745e840000000       | mov                 dword ptr [ebp - 0x18], 0x40

        $sequence_5 = { 50 8bc7 3575c98637 50 8bc3 e8???????? }
            // n = 6, score = 1000
            //   50                   | push                eax
            //   8bc7                 | mov                 eax, edi
            //   3575c98637           | xor                 eax, 0x3786c975
            //   50                   | push                eax
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_6 = { 85c0 750d 39730c 7303 }
            // n = 4, score = 1000
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   39730c               | cmp                 dword ptr [ebx + 0xc], esi
            //   7303                 | jae                 5

        $sequence_7 = { 0fa4ca14 c1e114 2bf9 1bda 6a00 48 50 }
            // n = 7, score = 1000
            //   0fa4ca14             | shld                edx, ecx, 0x14
            //   c1e114               | shl                 ecx, 0x14
            //   2bf9                 | sub                 edi, ecx
            //   1bda                 | sbb                 ebx, edx
            //   6a00                 | push                0
            //   48                   | dec                 eax
            //   50                   | push                eax

        $sequence_8 = { e8???????? 8b45fc 6a2a e8???????? }
            // n = 4, score = 1000
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   6a2a                 | push                0x2a
            //   e8????????           |                     

        $sequence_9 = { 7510 57 33ff 57 ff35???????? ff15???????? 8bc7 }
            // n = 7, score = 1000
            //   7510                 | jne                 0x12
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8bc7                 | mov                 eax, edi

    condition:
        7 of them and filesize < 147456
}