rule win_pony_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.pony."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pony"
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
        $sequence_0 = { d1e9 51 eb2e 66ad }
            // n = 4, score = 800
            //   d1e9                 | shr                 ecx, 1
            //   51                   | push                ecx
            //   eb2e                 | jmp                 0x30
            //   66ad                 | lodsw               ax, word ptr [esi]

        $sequence_1 = { 5b 8a03 8845fd 8a4301 8845fc }
            // n = 5, score = 800
            //   5b                   | pop                 ebx
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   8845fd               | mov                 byte ptr [ebp - 3], al
            //   8a4301               | mov                 al, byte ptr [ebx + 1]
            //   8845fc               | mov                 byte ptr [ebp - 4], al

        $sequence_2 = { ff761c 8f45f4 68???????? e8???????? d1e0 83c002 }
            // n = 6, score = 800
            //   ff761c               | push                dword ptr [esi + 0x1c]
            //   8f45f4               | pop                 dword ptr [ebp - 0xc]
            //   68????????           |                     
            //   e8????????           |                     
            //   d1e0                 | shl                 eax, 1
            //   83c002               | add                 eax, 2

        $sequence_3 = { ff75dc 8f45d8 c745d000000000 8d45cc 50 6a01 }
            // n = 6, score = 800
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   8f45d8               | pop                 dword ptr [ebp - 0x28]
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_4 = { ffb5f0f7ffff ff35???????? e8???????? 8985e8f7ffff 6a00 68???????? ffb5f0f7ffff }
            // n = 7, score = 800
            //   ffb5f0f7ffff         | push                dword ptr [ebp - 0x810]
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8985e8f7ffff         | mov                 dword ptr [ebp - 0x818], eax
            //   6a00                 | push                0
            //   68????????           |                     
            //   ffb5f0f7ffff         | push                dword ptr [ebp - 0x810]

        $sequence_5 = { bfffffffff 33f8 0bf9 33fa 8d9c1f91d386eb 035e24 c1c315 }
            // n = 7, score = 800
            //   bfffffffff           | mov                 edi, 0xffffffff
            //   33f8                 | xor                 edi, eax
            //   0bf9                 | or                  edi, ecx
            //   33fa                 | xor                 edi, edx
            //   8d9c1f91d386eb       | lea                 ebx, [edi + ebx - 0x14792c6f]
            //   035e24               | add                 ebx, dword ptr [esi + 0x24]
            //   c1c315               | rol                 ebx, 0x15

        $sequence_6 = { 7412 0fc8 3b45f4 7507 }
            // n = 4, score = 800
            //   7412                 | je                  0x14
            //   0fc8                 | bswap               eax
            //   3b45f4               | cmp                 eax, dword ptr [ebp - 0xc]
            //   7507                 | jne                 9

        $sequence_7 = { 8b45f4 0fc8 f7d0 50 ff7508 e8???????? }
            // n = 6, score = 800
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   0fc8                 | bswap               eax
            //   f7d0                 | not                 eax
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_8 = { 833d????????00 7505 2bc0 5b c9 c3 c745fc00000000 }
            // n = 7, score = 800
            //   833d????????00       |                     
            //   7505                 | jne                 7
            //   2bc0                 | sub                 eax, eax
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_9 = { 803800 7505 e9???????? ff7510 ff750c e8???????? }
            // n = 6, score = 800
            //   803800               | cmp                 byte ptr [eax], 0
            //   7505                 | jne                 7
            //   e9????????           |                     
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 262144
}