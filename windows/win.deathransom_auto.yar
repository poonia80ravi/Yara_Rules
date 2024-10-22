rule win_deathransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.deathransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
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
        $sequence_0 = { e8???????? 8b4d10 8d45bc 83c404 f7db 33d2 895dcc }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   83c404               | add                 esp, 4
            //   f7db                 | neg                 ebx
            //   33d2                 | xor                 edx, edx
            //   895dcc               | mov                 dword ptr [ebp - 0x34], ebx

        $sequence_1 = { 55 8bec 83ec20 53 8bda 894dfc 56 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec20               | sub                 esp, 0x20
            //   53                   | push                ebx
            //   8bda                 | mov                 ebx, edx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   56                   | push                esi

        $sequence_2 = { 8b7a10 8945dc 8b4218 8bc8 8b5a0c c1c007 c1c90b }
            // n = 7, score = 100
            //   8b7a10               | mov                 edi, dword ptr [edx + 0x10]
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b4218               | mov                 eax, dword ptr [edx + 0x18]
            //   8bc8                 | mov                 ecx, eax
            //   8b5a0c               | mov                 ebx, dword ptr [edx + 0xc]
            //   c1c007               | rol                 eax, 7
            //   c1c90b               | ror                 ecx, 0xb

        $sequence_3 = { 8d8d10feffff 8d4320 6800010000 51 50 e8???????? }
            // n = 6, score = 100
            //   8d8d10feffff         | lea                 ecx, [ebp - 0x1f0]
            //   8d4320               | lea                 eax, [ebx + 0x20]
            //   6800010000           | push                0x100
            //   51                   | push                ecx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 83ee01 0f8579ffffff 8d8528feffff 50 8d95c8feffff 8d8d68ffffff e8???????? }
            // n = 7, score = 100
            //   83ee01               | sub                 esi, 1
            //   0f8579ffffff         | jne                 0xffffff7f
            //   8d8528feffff         | lea                 eax, [ebp - 0x1d8]
            //   50                   | push                eax
            //   8d95c8feffff         | lea                 edx, [ebp - 0x138]
            //   8d8d68ffffff         | lea                 ecx, [ebp - 0x98]
            //   e8????????           |                     

        $sequence_5 = { 0bc8 0fb6421c c1e108 8d55c0 0bc8 0fbe05???????? 894df8 }
            // n = 7, score = 100
            //   0bc8                 | or                  ecx, eax
            //   0fb6421c             | movzx               eax, byte ptr [edx + 0x1c]
            //   c1e108               | shl                 ecx, 8
            //   8d55c0               | lea                 edx, [ebp - 0x40]
            //   0bc8                 | or                  ecx, eax
            //   0fbe05????????       |                     
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_6 = { 0f42d6 8b75e0 2bc7 3bcf 8b7df4 0f42c1 8bce }
            // n = 7, score = 100
            //   0f42d6               | cmovb               edx, esi
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   2bc7                 | sub                 eax, edi
            //   3bcf                 | cmp                 ecx, edi
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   0f42c1               | cmovb               eax, ecx
            //   8bce                 | mov                 ecx, esi

        $sequence_7 = { 83fe28 72dc 6a01 68???????? ff15???????? 6a00 57 }
            // n = 7, score = 100
            //   83fe28               | cmp                 esi, 0x28
            //   72dc                 | jb                  0xffffffde
            //   6a01                 | push                1
            //   68????????           |                     
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_8 = { 57 894df8 c745fc00000000 8975f0 895d0c 8b02 8bfe }
            // n = 7, score = 100
            //   57                   | push                edi
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   895d0c               | mov                 dword ptr [ebp + 0xc], ebx
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8bfe                 | mov                 edi, esi

        $sequence_9 = { 8d85c8feffff 50 e8???????? 83c40c be04000000 }
            // n = 5, score = 100
            //   8d85c8feffff         | lea                 eax, [ebp - 0x138]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   be04000000           | mov                 esi, 4

    condition:
        7 of them and filesize < 133120
}