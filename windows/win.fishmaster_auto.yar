rule win_fishmaster_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.fishmaster."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fishmaster"
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
        $sequence_0 = { 4883f81f 7736 498bc8 e8???????? 48c7471000000000 }
            // n = 5, score = 100
            //   4883f81f             | inc                 esp
            //   7736                 | mov                 eax, dword ptr [ebp + 0x2050]
            //   498bc8               | xor                 edx, edx
            //   e8????????           |                     
            //   48c7471000000000     | dec                 eax

        $sequence_1 = { 880c10 c644100100 eb17 440fb6c9 498bce e8???????? 4c8b4c2428 }
            // n = 7, score = 100
            //   880c10               | dec                 eax
            //   c644100100           | cmovae              eax, dword ptr [esp + 0x40]
            //   eb17                 | dec                 eax
            //   440fb6c9             | lea                 ecx, [esp + 0x40]
            //   498bce               | dec                 eax
            //   e8????????           |                     
            //   4c8b4c2428           | cmovae              ecx, dword ptr [esp + 0x40]

        $sequence_2 = { 7203 4c8b03 8d45ff 4863c8 }
            // n = 4, score = 100
            //   7203                 | jb                  0x9b5
            //   4c8b03               | dec                 eax
            //   8d45ff               | mov                 ecx, ebx
            //   4863c8               | dec                 eax

        $sequence_3 = { 4c897c2458 4d8d3c16 498bcf 4883c90f }
            // n = 4, score = 100
            //   4c897c2458           | jb                  0x760
            //   4d8d3c16             | dec                 eax
            //   498bcf               | mov                 ecx, dword ptr [ebp + 0x40]
            //   4883c90f             | dec                 eax

        $sequence_4 = { 488d85f0130000 488945e8 488d85f0070000 488945b8 }
            // n = 4, score = 100
            //   488d85f0130000       | mov                 byte ptr [eax + ecx], bh
            //   488945e8             | dec                 eax
            //   488d85f0070000       | cmp                 edx, 0x10
            //   488945b8             | jb                  0x2e9

        $sequence_5 = { 488b4b10 488b5318 488bc2 482bc1 4883f801 721f }
            // n = 6, score = 100
            //   488b4b10             | dec                 ecx
            //   488b5318             | mov                 edx, dword ptr [esi + 0x18]
            //   488bc2               | ret                 
            //   482bc1               | dec                 eax
            //   4883f801             | mov                 dword ptr [esp + 8], ebx
            //   721f                 | push                edi

        $sequence_6 = { 80f92b 750c 448bc7 89bc24a0000000 }
            // n = 4, score = 100
            //   80f92b               | mov                 dword ptr [esp + 0x38], esi
            //   750c                 | dec                 eax
            //   448bc7               | lea                 ecx, [esp + 0x68]
            //   89bc24a0000000       | dec                 eax

        $sequence_7 = { 4533c0 ba05000020 488bcb ff15???????? 488bcb ff15???????? c744243000010000 }
            // n = 7, score = 100
            //   4533c0               | dec                 eax
            //   ba05000020           | lea                 edx, [0x2152]
            //   488bcb               | mov                 dword ptr [esp + 0x30], 0x100
            //   ff15????????         |                     
            //   488bcb               | dec                 esp
            //   ff15????????         |                     
            //   c744243000010000     | mov                 dword ptr [esp + 0x28], esi

        $sequence_8 = { 410fbe4c0103 8d41bf 3c19 7705 8d71bf }
            // n = 5, score = 100
            //   410fbe4c0103         | ja                  0xaae
            //   8d41bf               | lea                 edx, [ecx + 4]
            //   3c19                 | jmp                 0xac5
            //   7705                 | cmp                 cl, 0x2b
            //   8d71bf               | ja                  0xab8

        $sequence_9 = { ff15???????? 488bf8 4c89742430 4489742428 4489742420 4533c9 4533c0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488bf8               | ret                 
            //   4c89742430           | dec                 eax
            //   4489742428           | mov                 dword ptr [esp + 8], ebx
            //   4489742420           | push                edi
            //   4533c9               | dec                 eax
            //   4533c0               | sub                 esp, 0x20

    condition:
        7 of them and filesize < 812032
}