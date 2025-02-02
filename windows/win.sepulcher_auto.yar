rule win_sepulcher_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sepulcher."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sepulcher"
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
        $sequence_0 = { 8b7508 57 33ff 894db8 8975b4 8945bc 85f6 }
            // n = 7, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   894db8               | mov                 dword ptr [ebp - 0x48], ecx
            //   8975b4               | mov                 dword ptr [ebp - 0x4c], esi
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   85f6                 | test                esi, esi

        $sequence_1 = { 57 68fa000000 6689850cfeffff ff15???????? ff15???????? 8b35???????? 50 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   68fa000000           | push                0xfa
            //   6689850cfeffff       | mov                 word ptr [ebp - 0x1f4], ax
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   50                   | push                eax

        $sequence_2 = { 0f2805???????? 668945d8 668945e0 33c0 66894dde 59 6a73 }
            // n = 7, score = 100
            //   0f2805????????       |                     
            //   668945d8             | mov                 word ptr [ebp - 0x28], ax
            //   668945e0             | mov                 word ptr [ebp - 0x20], ax
            //   33c0                 | xor                 eax, eax
            //   66894dde             | mov                 word ptr [ebp - 0x22], cx
            //   59                   | pop                 ecx
            //   6a73                 | push                0x73

        $sequence_3 = { 66898d00feffff e8???????? 83c418 68???????? 8d85bcf5ffff 50 }
            // n = 6, score = 100
            //   66898d00feffff       | mov                 word ptr [ebp - 0x200], cx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   68????????           |                     
            //   8d85bcf5ffff         | lea                 eax, [ebp - 0xa44]
            //   50                   | push                eax

        $sequence_4 = { 747f 8dbb68480000 8d8364480000 8db360480000 833f00 7411 }
            // n = 6, score = 100
            //   747f                 | je                  0x81
            //   8dbb68480000         | lea                 edi, [ebx + 0x4868]
            //   8d8364480000         | lea                 eax, [ebx + 0x4864]
            //   8db360480000         | lea                 esi, [ebx + 0x4860]
            //   833f00               | cmp                 dword ptr [edi], 0
            //   7411                 | je                  0x13

        $sequence_5 = { f2c3 f2e9e7030000 55 8bec a1???????? 83e01f 6a20 }
            // n = 7, score = 100
            //   f2c3                 | bnd ret             
            //   f2e9e7030000         | bnd jmp             0x3ed
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   83e01f               | and                 eax, 0x1f
            //   6a20                 | push                0x20

        $sequence_6 = { 33f6 c645ff00 2175f8 8bc1 }
            // n = 4, score = 100
            //   33f6                 | xor                 esi, esi
            //   c645ff00             | mov                 byte ptr [ebp - 1], 0
            //   2175f8               | and                 dword ptr [ebp - 8], esi
            //   8bc1                 | mov                 eax, ecx

        $sequence_7 = { 66393408 75f1 eb26 0fb7c3 c1e002 0fb7d3 }
            // n = 6, score = 100
            //   66393408             | cmp                 word ptr [eax + ecx], si
            //   75f1                 | jne                 0xfffffff3
            //   eb26                 | jmp                 0x28
            //   0fb7c3               | movzx               eax, bx
            //   c1e002               | shl                 eax, 2
            //   0fb7d3               | movzx               edx, bx

        $sequence_8 = { 8b4508 8365bc00 53 8b5d0c 56 57 8b7d10 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8365bc00             | and                 dword ptr [ebp - 0x44], 0
            //   53                   | push                ebx
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]

        $sequence_9 = { 0f84b8000000 83be5c48000000 0f84ab000000 57 8d85f8f7ffff }
            // n = 5, score = 100
            //   0f84b8000000         | je                  0xbe
            //   83be5c48000000       | cmp                 dword ptr [esi + 0x485c], 0
            //   0f84ab000000         | je                  0xb1
            //   57                   | push                edi
            //   8d85f8f7ffff         | lea                 eax, [ebp - 0x808]

    condition:
        7 of them and filesize < 279552
}