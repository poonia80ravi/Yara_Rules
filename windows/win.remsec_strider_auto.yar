rule win_remsec_strider_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.remsec_strider."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remsec_strider"
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
        $sequence_0 = { 7407 33c0 40 8906 eb0e 832600 ff5618 }
            // n = 7, score = 200
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   8906                 | mov                 dword ptr [esi], eax
            //   eb0e                 | jmp                 0x10
            //   832600               | and                 dword ptr [esi], 0
            //   ff5618               | call                dword ptr [esi + 0x18]

        $sequence_1 = { 8a4738 884638 8b473c 89463c 8b4744 894644 }
            // n = 6, score = 200
            //   8a4738               | mov                 al, byte ptr [edi + 0x38]
            //   884638               | mov                 byte ptr [esi + 0x38], al
            //   8b473c               | mov                 eax, dword ptr [edi + 0x3c]
            //   89463c               | mov                 dword ptr [esi + 0x3c], eax
            //   8b4744               | mov                 eax, dword ptr [edi + 0x44]
            //   894644               | mov                 dword ptr [esi + 0x44], eax

        $sequence_2 = { 53 33c0 56 57 8d7de4 ab ab }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d7de4               | lea                 edi, [ebp - 0x1c]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_3 = { 56 57 8d7de4 ab ab ab }
            // n = 6, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d7de4               | lea                 edi, [ebp - 0x1c]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_4 = { 6a08 50 ffd6 59 }
            // n = 4, score = 200
            //   6a08                 | push                8
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   59                   | pop                 ecx

        $sequence_5 = { 6803010000 50 ff15???????? 83c414 8d45f0 50 8b4608 }
            // n = 7, score = 200
            //   6803010000           | push                0x103
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]

        $sequence_6 = { 8b4610 83b808020000ff 7512 8b1d???????? }
            // n = 4, score = 200
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]
            //   83b808020000ff       | cmp                 dword ptr [eax + 0x208], -1
            //   7512                 | jne                 0x14
            //   8b1d????????         |                     

        $sequence_7 = { e8???????? 85c0 750a 8b06 6a01 8bce }
            // n = 6, score = 200
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6a01                 | push                1
            //   8bce                 | mov                 ecx, esi

        $sequence_8 = { 8b0481 8bc8 c1e908 0fb6c9 3bcf 77c2 }
            // n = 6, score = 200
            //   8b0481               | mov                 eax, dword ptr [ecx + eax*4]
            //   8bc8                 | mov                 ecx, eax
            //   c1e908               | shr                 ecx, 8
            //   0fb6c9               | movzx               ecx, cl
            //   3bcf                 | cmp                 ecx, edi
            //   77c2                 | ja                  0xffffffc4

        $sequence_9 = { 8b480c 668b31 663b32 751e }
            // n = 4, score = 200
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   668b31               | mov                 si, word ptr [ecx]
            //   663b32               | cmp                 si, word ptr [edx]
            //   751e                 | jne                 0x20

    condition:
        7 of them and filesize < 344064
}