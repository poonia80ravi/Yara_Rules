rule win_acidbox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.acidbox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acidbox"
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
        $sequence_0 = { 4983c003 488d4903 418840fe 8a41ff 4183c3fd }
            // n = 5, score = 400
            //   4983c003             | push                edi
            //   488d4903             | dec                 eax
            //   418840fe             | sub                 esp, 0x60
            //   8a41ff               | dec                 eax
            //   4183c3fd             | mov                 esi, ecx

        $sequence_1 = { 448bc8 b8f9ffffff 418bd6 83e27f 83c20b 41c1ee07 }
            // n = 6, score = 400
            //   448bc8               | mov                 dword ptr [esp + 0x48], 0x7551744e
            //   b8f9ffffff           | mov                 dword ptr [esp + 0x4c], 0x49797265
            //   418bd6               | mov                 word ptr [esp + 0x5e], 0x6461
            //   83e27f               | mov                 word ptr [esp + 0x5b], 0x6c
            //   83c20b               | mov                 word ptr [esp + 0x53], 0x656e
            //   41c1ee07             | mov                 byte ptr [esp + 0x59], 0x64

        $sequence_2 = { 89442420 85c0 7531 41f6461802 7412 488bce e8???????? }
            // n = 7, score = 400
            //   89442420             | test                eax, eax
            //   85c0                 | jne                 0xda
            //   7531                 | dec                 eax
            //   41f6461802           | mov                 dword ptr [esp + 0x20], esi
            //   7412                 | mov                 esi, 0x104
            //   488bce               | dec                 esp
            //   e8????????           |                     

        $sequence_3 = { 7413 8b477c 6644898c4788000000 ff477c ffca 75ed 8b4778 }
            // n = 7, score = 400
            //   7413                 | lea                 edx, [ebp - 0x58]
            //   8b477c               | inc                 ebp
            //   6644898c4788000000     | mov    ecx, eax
            //   ff477c               | test                eax, eax
            //   ffca                 | je                  0x113d
            //   75ed                 | cmp                 eax, 3
            //   8b4778               | jb                  0xef6

        $sequence_4 = { e8???????? 89442430 85c0 742c 488d8424c8000000 4889442420 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   89442430             | mov                 eax, dword ptr [ebx + 0x94]
            //   85c0                 | inc                 esp
            //   742c                 | mov                 edi, dword ptr [ebx + 0x9c]
            //   488d8424c8000000     | inc                 esp
            //   4889442420           | add                 edi, eax

        $sequence_5 = { 7446 488b08 488b4008 488908 }
            // n = 4, score = 400
            //   7446                 | jne                 0x24f
            //   488b08               | dec                 eax
            //   488b4008             | mov                 ecx, esi
            //   488908               | cmp                 ebx, eax

        $sequence_6 = { 4156 4883ec30 4d8bf0 488bfa 4c8bc9 33f6 4885c9 }
            // n = 7, score = 400
            //   4156                 | mov                 dword ptr [esp + 0x48], eax
            //   4883ec30             | dec                 eax
            //   4d8bf0               | test                eax, eax
            //   488bfa               | jne                 0x345
            //   4c8bc9               | mov                 ebx, 0xa0032604
            //   33f6                 | dec                 ecx
            //   4885c9               | mov                 edx, esi

        $sequence_7 = { 664401b493bc000000 8b83f0160000 412bc6 3983f4160000 753e 8b8384000000 85c0 }
            // n = 7, score = 400
            //   664401b493bc000000     | inc    ecx
            //   8b83f0160000         | mov                 edx, edx
            //   412bc6               | inc                 ecx
            //   3983f4160000         | sub                 ecx, edx
            //   753e                 | dec                 eax
            //   8b8384000000         | add                 edx, dword ptr [ebx + 0x10]
            //   85c0                 | jne                 0x1c90

        $sequence_8 = { 894718 418944244c 418bce 418bc6 458bc2 c1e010 81e100ff0000 }
            // n = 7, score = 400
            //   894718               | cmp                 ecx, 9
            //   418944244c           | jle                 0x1571
            //   418bce               | inc                 ecx
            //   418bc6               | mov                 edx, dword ptr [ecx + 0x28]
            //   458bc2               | lea                 eax, [ecx + ebx]
            //   c1e010               | inc                 ecx
            //   81e100ff0000         | mov                 dword ptr [ecx + 0x1714], eax

        $sequence_9 = { c740e4ffff0000 4885c9 750a b802110480 e9???????? 8b4108 }
            // n = 6, score = 400
            //   c740e4ffff0000       | mov                 eax, 0xc00
            //   4885c9               | mov                 dword ptr [ebp - 0x68], ebx
            //   750a                 | dec                 eax
            //   b802110480           | add                 esi, ebx
            //   e9????????           |                     
            //   8b4108               | mov                 dword ptr [ebp - 0x80], ebx

    condition:
        7 of them and filesize < 589824
}