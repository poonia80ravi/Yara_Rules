rule win_solarbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.solarbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.solarbot"
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
        $sequence_0 = { c745f800000000 c745f400000000 89df 57 89d0 50 }
            // n = 6, score = 300
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   89df                 | mov                 edi, ebx
            //   57                   | push                edi
            //   89d0                 | mov                 eax, edx
            //   50                   | push                eax

        $sequence_1 = { 7626 8a03 3c01 7220 fec8 741c }
            // n = 6, score = 300
            //   7626                 | jbe                 0x28
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   3c01                 | cmp                 al, 1
            //   7220                 | jb                  0x22
            //   fec8                 | dec                 al
            //   741c                 | je                  0x1e

        $sequence_2 = { 39ca 77dd 89d8 8b5df4 8b75f8 }
            // n = 5, score = 300
            //   39ca                 | cmp                 edx, ecx
            //   77dd                 | ja                  0xffffffdf
            //   89d8                 | mov                 eax, ebx
            //   8b5df4               | mov                 ebx, dword ptr [ebp - 0xc]
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]

        $sequence_3 = { 8916 8d55f8 890a 895dfc ff75fc 0fb755fa 52 }
            // n = 7, score = 300
            //   8916                 | mov                 dword ptr [esi], edx
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   890a                 | mov                 dword ptr [edx], ecx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   0fb755fa             | movzx               edx, word ptr [ebp - 6]
            //   52                   | push                edx

        $sequence_4 = { 0345f8 40 89c3 83fe01 }
            // n = 4, score = 300
            //   0345f8               | add                 eax, dword ptr [ebp - 8]
            //   40                   | inc                 eax
            //   89c3                 | mov                 ebx, eax
            //   83fe01               | cmp                 esi, 1

        $sequence_5 = { 6a04 8d85e0faffff 50 ffb58cf9ffff ffb5e4faffff 8b9510f9ffff }
            // n = 6, score = 300
            //   6a04                 | push                4
            //   8d85e0faffff         | lea                 eax, [ebp - 0x520]
            //   50                   | push                eax
            //   ffb58cf9ffff         | push                dword ptr [ebp - 0x674]
            //   ffb5e4faffff         | push                dword ptr [ebp - 0x51c]
            //   8b9510f9ffff         | mov                 edx, dword ptr [ebp - 0x6f0]

        $sequence_6 = { 83ec28 895dd8 8975dc 897de0 8b5d08 8b750c 8b7d10 }
            // n = 7, score = 300
            //   83ec28               | sub                 esp, 0x28
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]

        $sequence_7 = { 50 e8???????? 89d8 50 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   89d8                 | mov                 eax, ebx
            //   50                   | push                eax

        $sequence_8 = { b800000000 c745fc00000000 b80d000000 8b4df4 f721 }
            // n = 5, score = 300
            //   b800000000           | mov                 eax, 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   b80d000000           | mov                 eax, 0xd
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   f721                 | mul                 dword ptr [ecx]

        $sequence_9 = { 8b451c c745ec00000000 6a00 6a00 6a00 6a00 }
            // n = 6, score = 300
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 204800
}