rule win_atomsilo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.atomsilo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atomsilo"
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
        $sequence_0 = { 4156 4157 4881ec48010000 48c7842480000000feffffff 488b05???????? 4833c4 4889842430010000 }
            // n = 7, score = 100
            //   4156                 | mul                 dword ptr [esp + 0x30]
            //   4157                 | dec                 esp
            //   4881ec48010000       | cmp                 eax, ecx
            //   48c7842480000000feffffff     | dec    ecx
            //   488b05????????       |                     
            //   4833c4               | adc                 edx, edi
            //   4889842430010000     | dec                 esp

        $sequence_1 = { 4883d200 4c03fa 49f76570 4903c0 493bc0 49894370 4d8b442478 }
            // n = 7, score = 100
            //   4883d200             | mov                 edx, dword ptr [eax]
            //   4c03fa               | je                  0x17f
            //   49f76570             | dec                 eax
            //   4903c0               | mov                 eax, dword ptr [edx]
            //   493bc0               | dec                 ecx
            //   49894370             | mov                 edx, ecx
            //   4d8b442478           | dec                 eax

        $sequence_2 = { 488bc7 4883fa10 7203 488b07 488d1c08 41b80e000000 488d1535f00500 }
            // n = 7, score = 100
            //   488bc7               | mov                 eax, dword ptr [ebx + 0x78]
            //   4883fa10             | dec                 eax
            //   7203                 | cmp                 dword ptr [ebx + 0x70], eax
            //   488b07               | cmovb               ecx, edx
            //   488d1c08             | dec                 eax
            //   41b80e000000         | mov                 edx, dword ptr [ebx + 0x80]
            //   488d1535f00500       | mov                 ecx, 0x80

        $sequence_3 = { e8???????? 4533c9 4c8bc6 498bd6 488d4c2458 e8???????? 498b4710 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4533c9               | call                dword ptr [eax + 8]
            //   4c8bc6               | nop                 
            //   498bd6               | dec                 eax
            //   488d4c2458           | mov                 ecx, eax
            //   e8????????           |                     
            //   498b4710             | dec                 eax

        $sequence_4 = { ff5710 90 488d9520010000 488d8d60040000 e8???????? 488b4688 48637804 }
            // n = 7, score = 100
            //   ff5710               | dec                 eax
            //   90                   | lea                 eax, [0x3075]
            //   488d9520010000       | mov                 dword ptr [ebp - 0xd], edx
            //   488d8d60040000       | movaps              xmm1, xmmword ptr [ebp - 0x19]
            //   e8????????           |                     
            //   488b4688             | dec                 eax
            //   48637804             | mov                 dword ptr [ebp + 0x17], eax

        $sequence_5 = { c1c205 4433442428 418bcb 448b742404 0bcf 4123ca 41d1c0 }
            // n = 7, score = 100
            //   c1c205               | cmp                 ecx, edx
            //   4433442428           | je                  0x50
            //   418bcb               | dec                 eax
            //   448b742404           | mov                 ebx, dword ptr [esp + 0x50]
            //   0bcf                 | dec                 ebp
            //   4123ca               | test                edi, edi
            //   41d1c0               | je                  0x69

        $sequence_6 = { 90 4584ed 742a ffc6 83fe40 750c }
            // n = 6, score = 100
            //   90                   | lea                 edx, [0x5583b]
            //   4584ed               | dec                 eax
            //   742a                 | lea                 ebx, [esp + 0x48]
            //   ffc6                 | dec                 eax
            //   83fe40               | cmp                 edx, 0x10
            //   750c                 | dec                 eax

        $sequence_7 = { ff15???????? eb0b 498bce ff15???????? 33c0 4c8bac2410140000 4c8ba42408140000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   eb0b                 | lea                 eax, [0x31f2e]
            //   498bce               | dec                 eax
            //   ff15????????         |                     
            //   33c0                 | mov                 dword ptr [ebx], eax
            //   4c8bac2410140000     | dec                 eax
            //   4c8ba42408140000     | and                 dword ptr [ebx + 0x100], 0

        $sequence_8 = { 488945d0 33c0 897d30 c7459061000000 c6459431 c6459534 c6459623 }
            // n = 7, score = 100
            //   488945d0             | cmp                 dword ptr [edx], 0
            //   33c0                 | jne                 0x1ea
            //   897d30               | dec                 eax
            //   c7459061000000       | mov                 eax, dword ptr [ecx + 0x18]
            //   c6459431             | cmp                 dword ptr [ecx + 0x28], 1
            //   c6459534             | jne                 0x224
            //   c6459623             | dec                 eax

        $sequence_9 = { 4c8d0508200700 488bd0 488d8c2488000000 e8???????? 90 4c8bc7 488bd0 }
            // n = 7, score = 100
            //   4c8d0508200700       | mov                 ecx, dword ptr [edx]
            //   488bd0               | dec                 eax
            //   488d8c2488000000     | lea                 eax, [ecx - 1]
            //   e8????????           |                     
            //   90                   | dec                 eax
            //   4c8bc7               | mov                 dword ptr [edx], eax
            //   488bd0               | dec                 eax

    condition:
        7 of them and filesize < 1785856
}