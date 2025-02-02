rule win_grillmark_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.grillmark."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grillmark"
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
        $sequence_0 = { 897dd8 66c745dc0500 56 ff15???????? 3bc6 740e ff7510 }
            // n = 7, score = 300
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi
            //   66c745dc0500         | mov                 word ptr [ebp - 0x24], 5
            //   56                   | push                esi
            //   ff15????????         |                     
            //   3bc6                 | cmp                 eax, esi
            //   740e                 | je                  0x10
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_1 = { ff15???????? 8d85fcfeffff 68???????? 50 e8???????? ff7514 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff7514               | push                dword ptr [ebp + 0x14]

        $sequence_2 = { 8365fc00 e8???????? e8???????? 83f840 }
            // n = 4, score = 300
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   e8????????           |                     
            //   83f840               | cmp                 eax, 0x40

        $sequence_3 = { 8945ec 0f8407010000 56 56 6a03 56 }
            // n = 6, score = 300
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   0f8407010000         | je                  0x10d
            //   56                   | push                esi
            //   56                   | push                esi
            //   6a03                 | push                3
            //   56                   | push                esi

        $sequence_4 = { ff15???????? 85c0 ebd1 c745f401000000 3bfb }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   ebd1                 | jmp                 0xffffffd3
            //   c745f401000000       | mov                 dword ptr [ebp - 0xc], 1
            //   3bfb                 | cmp                 edi, ebx

        $sequence_5 = { c3 55 8bec 81ec48030000 80a5bcfdffff00 }
            // n = 5, score = 300
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec48030000         | sub                 esp, 0x348
            //   80a5bcfdffff00       | and                 byte ptr [ebp - 0x244], 0

        $sequence_6 = { 3ada 74f2 47 803f00 }
            // n = 4, score = 300
            //   3ada                 | cmp                 bl, dl
            //   74f2                 | je                  0xfffffff4
            //   47                   | inc                 edi
            //   803f00               | cmp                 byte ptr [edi], 0

        $sequence_7 = { ff75fc 03c6 46 e8???????? 3bf0 59 72c5 }
            // n = 7, score = 300
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   03c6                 | add                 eax, esi
            //   46                   | inc                 esi
            //   e8????????           |                     
            //   3bf0                 | cmp                 esi, eax
            //   59                   | pop                 ecx
            //   72c5                 | jb                  0xffffffc7

        $sequence_8 = { 03c6 46 e8???????? 3bf0 59 72c5 8b45fc }
            // n = 7, score = 300
            //   03c6                 | add                 eax, esi
            //   46                   | inc                 esi
            //   e8????????           |                     
            //   3bf0                 | cmp                 esi, eax
            //   59                   | pop                 ecx
            //   72c5                 | jb                  0xffffffc7
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_9 = { c745e80c000000 ff15???????? 85c0 7478 8d4594 c7459444000000 }
            // n = 6, score = 300
            //   c745e80c000000       | mov                 dword ptr [ebp - 0x18], 0xc
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7478                 | je                  0x7a
            //   8d4594               | lea                 eax, [ebp - 0x6c]
            //   c7459444000000       | mov                 dword ptr [ebp - 0x6c], 0x44

    condition:
        7 of them and filesize < 212992
}