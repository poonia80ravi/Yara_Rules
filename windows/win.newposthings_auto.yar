rule win_newposthings_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.newposthings."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newposthings"
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
        $sequence_0 = { 6aff 6a00 8d45c0 c741140f000000 c7411000000000 50 c60100 }
            // n = 7, score = 100
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   8d45c0               | lea                 eax, [ebp - 0x40]
            //   c741140f000000       | mov                 dword ptr [ecx + 0x14], 0xf
            //   c7411000000000       | mov                 dword ptr [ecx + 0x10], 0
            //   50                   | push                eax
            //   c60100               | mov                 byte ptr [ecx], 0

        $sequence_1 = { 5d c3 8d85f8feffff 50 68???????? e8???????? 8d85f8feffff }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]

        $sequence_2 = { e8???????? eb2a 807de000 7504 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   eb2a                 | jmp                 0x2c
            //   807de000             | cmp                 byte ptr [ebp - 0x20], 0
            //   7504                 | jne                 6

        $sequence_3 = { c20800 687cc40110 e8???????? 687cc40110 }
            // n = 4, score = 100
            //   c20800               | ret                 8
            //   687cc40110           | push                0x1001c47c
            //   e8????????           |                     
            //   687cc40110           | push                0x1001c47c

        $sequence_4 = { 5b c3 33c0 648b0d00000000 81790430330110 7510 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   648b0d00000000       | mov                 ecx, dword ptr fs:[0]
            //   81790430330110       | cmp                 dword ptr [ecx + 4], 0x10013330
            //   7510                 | jne                 0x12

        $sequence_5 = { 50 c644245c00 8bce e8???????? 8bf0 eb02 33f6 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   c644245c00           | mov                 byte ptr [esp + 0x5c], 0
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi

        $sequence_6 = { c645fc08 6800040000 8d4614 50 }
            // n = 4, score = 100
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   6800040000           | push                0x400
            //   8d4614               | lea                 eax, [esi + 0x14]
            //   50                   | push                eax

        $sequence_7 = { c1e902 f3a5 8d8508feffff 8bca 50 83e103 68???????? }
            // n = 7, score = 100
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8d8508feffff         | lea                 eax, [ebp - 0x1f8]
            //   8bca                 | mov                 ecx, edx
            //   50                   | push                eax
            //   83e103               | and                 ecx, 3
            //   68????????           |                     

        $sequence_8 = { 83bd38feffff10 720e ffb524feffff e8???????? 83c404 68c8000000 8d8524ffffff }
            // n = 7, score = 100
            //   83bd38feffff10       | cmp                 dword ptr [ebp - 0x1c8], 0x10
            //   720e                 | jb                  0x10
            //   ffb524feffff         | push                dword ptr [ebp - 0x1dc]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   68c8000000           | push                0xc8
            //   8d8524ffffff         | lea                 eax, [ebp - 0xdc]

        $sequence_9 = { 837d2010 720b ff750c e8???????? 83c404 c745200f000000 }
            // n = 6, score = 100
            //   837d2010             | cmp                 dword ptr [ebp + 0x20], 0x10
            //   720b                 | jb                  0xd
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c745200f000000       | mov                 dword ptr [ebp + 0x20], 0xf

    condition:
        7 of them and filesize < 827392
}