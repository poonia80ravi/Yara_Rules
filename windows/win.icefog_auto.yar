rule win_icefog_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.icefog."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icefog"
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
        $sequence_0 = { 6a00 6a00 6a00 6a0d 51 e8???????? 8b75e8 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a0d                 | push                0xd
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b75e8               | mov                 esi, dword ptr [ebp - 0x18]

        $sequence_1 = { 8b15???????? 52 e8???????? 83c408 5e 5d c3 }
            // n = 7, score = 200
            //   8b15????????         |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_2 = { 8b4310 8b4c0710 8b55fc 51 6a00 6a77 52 }
            // n = 7, score = 200
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]
            //   8b4c0710             | mov                 ecx, dword ptr [edi + eax + 0x10]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a77                 | push                0x77
            //   52                   | push                edx

        $sequence_3 = { e8???????? 83c408 85c0 751c 394518 7517 8a5514 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   751c                 | jne                 0x1e
            //   394518               | cmp                 dword ptr [ebp + 0x18], eax
            //   7517                 | jne                 0x19
            //   8a5514               | mov                 dl, byte ptr [ebp + 0x14]

        $sequence_4 = { 8bd8 7509 8b4d0c 8b5104 895510 8b4510 50 }
            // n = 7, score = 200
            //   8bd8                 | mov                 ebx, eax
            //   7509                 | jne                 0xb
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   895510               | mov                 dword ptr [ebp + 0x10], edx
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax

        $sequence_5 = { 818d40ffffff00002000 dc35???????? dd9d38ffffff eb0a c78540ffffff00000000 83bd1cffffff00 dd8538ffffff }
            // n = 7, score = 200
            //   818d40ffffff00002000     | or    dword ptr [ebp - 0xc0], 0x200000
            //   dc35????????         |                     
            //   dd9d38ffffff         | fstp                qword ptr [ebp - 0xc8]
            //   eb0a                 | jmp                 0xc
            //   c78540ffffff00000000     | mov    dword ptr [ebp - 0xc0], 0
            //   83bd1cffffff00       | cmp                 dword ptr [ebp - 0xe4], 0
            //   dd8538ffffff         | fld                 qword ptr [ebp - 0xc8]

        $sequence_6 = { dd05???????? 8b9568feffff eb0c 8db59cfeffff 89b594feffff 33c0 85d2 }
            // n = 7, score = 200
            //   dd05????????         |                     
            //   8b9568feffff         | mov                 edx, dword ptr [ebp - 0x198]
            //   eb0c                 | jmp                 0xe
            //   8db59cfeffff         | lea                 esi, [ebp - 0x164]
            //   89b594feffff         | mov                 dword ptr [ebp - 0x16c], esi
            //   33c0                 | xor                 eax, eax
            //   85d2                 | test                edx, edx

        $sequence_7 = { 53 e8???????? 83c418 898578ffffff 85c0 7544 8b17 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   898578ffffff         | mov                 dword ptr [ebp - 0x88], eax
            //   85c0                 | test                eax, eax
            //   7544                 | jne                 0x46
            //   8b17                 | mov                 edx, dword ptr [edi]

        $sequence_8 = { 8b55f8 52 e8???????? 8b45f4 6a00 53 50 }
            // n = 7, score = 200
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_9 = { 8be5 5d c3 3c02 7533 837d0800 0f8549010000 }
            // n = 7, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3c02                 | cmp                 al, 2
            //   7533                 | jne                 0x35
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   0f8549010000         | jne                 0x14f

    condition:
        7 of them and filesize < 1187840
}