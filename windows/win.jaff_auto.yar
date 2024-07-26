rule win_jaff_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.jaff."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jaff"
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
        $sequence_0 = { 50 8975e0 c645e801 c645fd00 ff15???????? 8d8598fbffff 83c40c }
            // n = 7, score = 600
            //   50                   | push                eax
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   c645e801             | mov                 byte ptr [ebp - 0x18], 1
            //   c645fd00             | mov                 byte ptr [ebp - 3], 0
            //   ff15????????         |                     
            //   8d8598fbffff         | lea                 eax, [ebp - 0x468]
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 8b55f8 8945d4 8b450c 8b08 0fbe0411 8d9d74ffffff }
            // n = 6, score = 600
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   0fbe0411             | movsx               eax, byte ptr [ecx + edx]
            //   8d9d74ffffff         | lea                 ebx, [ebp - 0x8c]

        $sequence_2 = { 884df8 ffd3 50 ff15???????? 33c9 }
            // n = 5, score = 600
            //   884df8               | mov                 byte ptr [ebp - 8], cl
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx

        $sequence_3 = { 8b4d08 8b07 56 8b31 8bcb }
            // n = 5, score = 600
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   56                   | push                esi
            //   8b31                 | mov                 esi, dword ptr [ecx]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_4 = { 8b4dd4 66890471 46 8975d8 8b4d0c ff45f4 }
            // n = 6, score = 600
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   66890471             | mov                 word ptr [ecx + esi*2], ax
            //   46                   | inc                 esi
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   ff45f4               | inc                 dword ptr [ebp - 0xc]

        $sequence_5 = { 8d55fc 52 50 51 56 ffd3 }
            // n = 6, score = 600
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   52                   | push                edx
            //   50                   | push                eax
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ffd3                 | call                ebx

        $sequence_6 = { 53 56 e8???????? 8b5510 8b450c 52 50 }
            // n = 7, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_7 = { c645e401 ffd3 50 ff15???????? 8945d8 8d45d8 }
            // n = 6, score = 600
            //   c645e401             | mov                 byte ptr [ebp - 0x1c], 1
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8d45d8               | lea                 eax, [ebp - 0x28]

        $sequence_8 = { 8d044a 2bfa 0fb710 0fb73438 663bd6 }
            // n = 5, score = 600
            //   8d044a               | lea                 eax, [edx + ecx*2]
            //   2bfa                 | sub                 edi, edx
            //   0fb710               | movzx               edx, word ptr [eax]
            //   0fb73438             | movzx               esi, word ptr [eax + edi]
            //   663bd6               | cmp                 dx, si

        $sequence_9 = { 895608 8a400c 51 6a08 88460c ffd7 50 }
            // n = 7, score = 600
            //   895608               | mov                 dword ptr [esi + 8], edx
            //   8a400c               | mov                 al, byte ptr [eax + 0xc]
            //   51                   | push                ecx
            //   6a08                 | push                8
            //   88460c               | mov                 byte ptr [esi + 0xc], al
            //   ffd7                 | call                edi
            //   50                   | push                eax

    condition:
        7 of them and filesize < 106496
}