rule win_mmon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mmon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mmon"
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
        $sequence_0 = { 6a00 50 e8???????? eb46 8d542414 52 6800100000 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   eb46                 | jmp                 0x48
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   52                   | push                edx
            //   6800100000           | push                0x1000

        $sequence_1 = { 8bc7 c1f805 c1e606 033485606a4200 8b45f8 }
            // n = 5, score = 100
            //   8bc7                 | mov                 eax, edi
            //   c1f805               | sar                 eax, 5
            //   c1e606               | shl                 esi, 6
            //   033485606a4200       | add                 esi, dword ptr [eax*4 + 0x426a60]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_2 = { 8d4dd0 2bc1 8d57f1 83e80f 899554ffffff 898548ffffff 8d642400 }
            // n = 7, score = 100
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   2bc1                 | sub                 eax, ecx
            //   8d57f1               | lea                 edx, [edi - 0xf]
            //   83e80f               | sub                 eax, 0xf
            //   899554ffffff         | mov                 dword ptr [ebp - 0xac], edx
            //   898548ffffff         | mov                 dword ptr [ebp - 0xb8], eax
            //   8d642400             | lea                 esp, [esp]

        $sequence_3 = { 75f9 2bc7 50 56 8d8d78ffffff }
            // n = 5, score = 100
            //   75f9                 | jne                 0xfffffffb
            //   2bc7                 | sub                 eax, edi
            //   50                   | push                eax
            //   56                   | push                esi
            //   8d8d78ffffff         | lea                 ecx, [ebp - 0x88]

        $sequence_4 = { c745ec90cf4000 894df8 8945fc 64a100000000 8945e8 8d45e8 64a300000000 }
            // n = 7, score = 100
            //   c745ec90cf4000       | mov                 dword ptr [ebp - 0x14], 0x40cf90
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   64a300000000         | mov                 dword ptr fs:[0], eax

        $sequence_5 = { 40 0080af4000a4 af 40 0023 }
            // n = 5, score = 100
            //   40                   | inc                 eax
            //   0080af4000a4         | add                 byte ptr [eax - 0x5bffbf51], al
            //   af                   | scasd               eax, dword ptr es:[edi]
            //   40                   | inc                 eax
            //   0023                 | add                 byte ptr [ebx], ah

        $sequence_6 = { 0f8cae010000 3c39 0f8fa6010000 8b854cffffff }
            // n = 4, score = 100
            //   0f8cae010000         | jl                  0x1b4
            //   3c39                 | cmp                 al, 0x39
            //   0f8fa6010000         | jg                  0x1ac
            //   8b854cffffff         | mov                 eax, dword ptr [ebp - 0xb4]

        $sequence_7 = { 8b4de4 8b75e8 ff05???????? 0375d4 8975e8 }
            // n = 5, score = 100
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   8b75e8               | mov                 esi, dword ptr [ebp - 0x18]
            //   ff05????????         |                     
            //   0375d4               | add                 esi, dword ptr [ebp - 0x2c]
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi

        $sequence_8 = { 895dd0 8945d8 8bf8 897dd4 8b5dd0 ebab c745e4c4e14100 }
            // n = 7, score = 100
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8bf8                 | mov                 edi, eax
            //   897dd4               | mov                 dword ptr [ebp - 0x2c], edi
            //   8b5dd0               | mov                 ebx, dword ptr [ebp - 0x30]
            //   ebab                 | jmp                 0xffffffad
            //   c745e4c4e14100       | mov                 dword ptr [ebp - 0x1c], 0x41e1c4

        $sequence_9 = { 33d2 b9???????? 57 8bc2 c1f805 8b0485606a4200 }
            // n = 6, score = 100
            //   33d2                 | xor                 edx, edx
            //   b9????????           |                     
            //   57                   | push                edi
            //   8bc2                 | mov                 eax, edx
            //   c1f805               | sar                 eax, 5
            //   8b0485606a4200       | mov                 eax, dword ptr [eax*4 + 0x426a60]

    condition:
        7 of them and filesize < 356352
}