rule win_rad_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.rad."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rad"
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
        $sequence_0 = { 8bc8 ff15???????? 8b10 8bc8 }
            // n = 4, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8bc8                 | mov                 ecx, eax

        $sequence_1 = { 57 7230 8b5d10 8b7310 8b3d???????? 85f6 740f }
            // n = 7, score = 100
            //   57                   | push                edi
            //   7230                 | jb                  0x32
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b7310               | mov                 esi, dword ptr [ebx + 0x10]
            //   8b3d????????         |                     
            //   85f6                 | test                esi, esi
            //   740f                 | je                  0x11

        $sequence_2 = { c684245402000006 ff15???????? 8db424e0000000 8bf8 c684245002000004 e8???????? b9???????? }
            // n = 7, score = 100
            //   c684245402000006     | mov                 byte ptr [esp + 0x254], 6
            //   ff15????????         |                     
            //   8db424e0000000       | lea                 esi, [esp + 0xe0]
            //   8bf8                 | mov                 edi, eax
            //   c684245002000004     | mov                 byte ptr [esp + 0x250], 4
            //   e8????????           |                     
            //   b9????????           |                     

        $sequence_3 = { 8be5 5d c3 8b4db0 8b11 8b4204 ffd0 }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b4db0               | mov                 ecx, dword ptr [ebp - 0x50]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   ffd0                 | call                eax

        $sequence_4 = { 56 57 7230 8b5d10 8b7310 8b3d???????? 85f6 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   7230                 | jb                  0x32
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b7310               | mov                 esi, dword ptr [ebx + 0x10]
            //   8b3d????????         |                     
            //   85f6                 | test                esi, esi

        $sequence_5 = { ff85c4fcffff 894704 8b4804 8901 }
            // n = 4, score = 100
            //   ff85c4fcffff         | inc                 dword ptr [ebp - 0x33c]
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_6 = { b8???????? 8dbc242c010000 e8???????? 8bcf 51 }
            // n = 5, score = 100
            //   b8????????           |                     
            //   8dbc242c010000       | lea                 edi, [esp + 0x12c]
            //   e8????????           |                     
            //   8bcf                 | mov                 ecx, edi
            //   51                   | push                ecx

        $sequence_7 = { 8bff 668b19 663b18 750b 83c102 83c002 4a }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   668b19               | mov                 bx, word ptr [ecx]
            //   663b18               | cmp                 bx, word ptr [eax]
            //   750b                 | jne                 0xd
            //   83c102               | add                 ecx, 2
            //   83c002               | add                 eax, 2
            //   4a                   | dec                 edx

        $sequence_8 = { c7859cfbffff0f000000 899d98fbffff 889d88fbffff ff15???????? 3bc3 8b1d???????? 7403 }
            // n = 7, score = 100
            //   c7859cfbffff0f000000     | mov    dword ptr [ebp - 0x464], 0xf
            //   899d98fbffff         | mov                 dword ptr [ebp - 0x468], ebx
            //   889d88fbffff         | mov                 byte ptr [ebp - 0x478], bl
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   8b1d????????         |                     
            //   7403                 | je                  5

        $sequence_9 = { 83c404 8d45b4 50 8bce c745e40f000000 897de0 c645d000 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   8d45b4               | lea                 eax, [ebp - 0x4c]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   c745e40f000000       | mov                 dword ptr [ebp - 0x1c], 0xf
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   c645d000             | mov                 byte ptr [ebp - 0x30], 0

    condition:
        7 of them and filesize < 207872
}