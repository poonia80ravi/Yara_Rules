rule win_nemim_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.nemim."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemim"
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
        $sequence_0 = { 884657 8d4618 c1e908 c1ea10 50 56 884e55 }
            // n = 7, score = 200
            //   884657               | mov                 byte ptr [esi + 0x57], al
            //   8d4618               | lea                 eax, [esi + 0x18]
            //   c1e908               | shr                 ecx, 8
            //   c1ea10               | shr                 edx, 0x10
            //   50                   | push                eax
            //   56                   | push                esi
            //   884e55               | mov                 byte ptr [esi + 0x55], cl

        $sequence_1 = { c744241000400100 50 51 e8???????? 33d2 89542404 }
            // n = 6, score = 200
            //   c744241000400100     | mov                 dword ptr [esp + 0x10], 0x14000
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   89542404             | mov                 dword ptr [esp + 4], edx

        $sequence_2 = { ff15???????? ff0d???????? 3b2d???????? 7d1d 8dbe40744300 8d4714 b905000000 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   ff0d????????         |                     
            //   3b2d????????         |                     
            //   7d1d                 | jge                 0x1f
            //   8dbe40744300         | lea                 edi, [esi + 0x437440]
            //   8d4714               | lea                 eax, [edi + 0x14]
            //   b905000000           | mov                 ecx, 5

        $sequence_3 = { 53 6880000000 50 ffd7 6804010000 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   6880000000           | push                0x80
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   6804010000           | push                0x104

        $sequence_4 = { 8b4e08 c1e910 88480a 8b5608 }
            // n = 4, score = 200
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   c1e910               | shr                 ecx, 0x10
            //   88480a               | mov                 byte ptr [eax + 0xa], cl
            //   8b5608               | mov                 edx, dword ptr [esi + 8]

        $sequence_5 = { c3 33c0 c3 83ec10 8364240000 55 }
            // n = 6, score = 200
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   83ec10               | sub                 esp, 0x10
            //   8364240000           | and                 dword ptr [esp], 0
            //   55                   | push                ebp

        $sequence_6 = { 895dec c745e8548b4200 8b4508 895dfc 3bc3 }
            // n = 5, score = 200
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   c745e8548b4200       | mov                 dword ptr [ebp - 0x18], 0x428b54
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   3bc3                 | cmp                 eax, ebx

        $sequence_7 = { 8bfe 03c1 33f9 33f8 03fd 8b6c242c }
            // n = 6, score = 200
            //   8bfe                 | mov                 edi, esi
            //   03c1                 | add                 eax, ecx
            //   33f9                 | xor                 edi, ecx
            //   33f8                 | xor                 edi, eax
            //   03fd                 | add                 edi, ebp
            //   8b6c242c             | mov                 ebp, dword ptr [esp + 0x2c]

        $sequence_8 = { c746543f3f4200 7531 6a40 e8???????? 59 }
            // n = 5, score = 200
            //   c746543f3f4200       | mov                 dword ptr [esi + 0x54], 0x423f3f
            //   7531                 | jne                 0x33
            //   6a40                 | push                0x40
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_9 = { 33d2 89542404 85c0 6689542408 0f85c5000000 56 8d742428 }
            // n = 7, score = 200
            //   33d2                 | xor                 edx, edx
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   85c0                 | test                eax, eax
            //   6689542408           | mov                 word ptr [esp + 8], dx
            //   0f85c5000000         | jne                 0xcb
            //   56                   | push                esi
            //   8d742428             | lea                 esi, [esp + 0x28]

    condition:
        7 of them and filesize < 499712
}