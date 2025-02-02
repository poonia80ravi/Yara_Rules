rule win_unidentified_061_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.unidentified_061."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_061"
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
        $sequence_0 = { bf???????? 57 ff15???????? 57 c705????????01000000 ff15???????? }
            // n = 6, score = 200
            //   bf????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   c705????????01000000     |     
            //   ff15????????         |                     

        $sequence_1 = { 0f8402010000 c1e708 56 81c7???????? 57 ff15???????? ff05???????? }
            // n = 7, score = 200
            //   0f8402010000         | je                  0x108
            //   c1e708               | shl                 edi, 8
            //   56                   | push                esi
            //   81c7????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff05????????         |                     

        $sequence_2 = { 8d041e 50 ff15???????? 6a00 83c61a }
            // n = 5, score = 200
            //   8d041e               | lea                 eax, [esi + ebx]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   83c61a               | add                 esi, 0x1a

        $sequence_3 = { 8d45d0 50 89b588fbffff 89b58cfcffff e8???????? }
            // n = 5, score = 200
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax
            //   89b588fbffff         | mov                 dword ptr [ebp - 0x478], esi
            //   89b58cfcffff         | mov                 dword ptr [ebp - 0x374], esi
            //   e8????????           |                     

        $sequence_4 = { 53 ff36 ff15???????? ff36 8b3d???????? }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   ff36                 | push                dword ptr [esi]
            //   ff15????????         |                     
            //   ff36                 | push                dword ptr [esi]
            //   8b3d????????         |                     

        $sequence_5 = { 8a0a 84c9 740b 380e 7507 46 42 }
            // n = 7, score = 200
            //   8a0a                 | mov                 cl, byte ptr [edx]
            //   84c9                 | test                cl, cl
            //   740b                 | je                  0xd
            //   380e                 | cmp                 byte ptr [esi], cl
            //   7507                 | jne                 9
            //   46                   | inc                 esi
            //   42                   | inc                 edx

        $sequence_6 = { c60700 5f 5e 5b 5d c21000 55 }
            // n = 7, score = 200
            //   c60700               | mov                 byte ptr [edi], 0
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   55                   | push                ebp

        $sequence_7 = { 83c574 c9 c20400 ff456c 8345600c 8345640c 817d60a0050000 }
            // n = 7, score = 200
            //   83c574               | add                 ebp, 0x74
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   ff456c               | inc                 dword ptr [ebp + 0x6c]
            //   8345600c             | add                 dword ptr [ebp + 0x60], 0xc
            //   8345640c             | add                 dword ptr [ebp + 0x64], 0xc
            //   817d60a0050000       | cmp                 dword ptr [ebp + 0x60], 0x5a0

        $sequence_8 = { ff15???????? 5e 5f 8bc3 5b c20800 57 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   8bc3                 | mov                 eax, ebx
            //   5b                   | pop                 ebx
            //   c20800               | ret                 8
            //   57                   | push                edi

        $sequence_9 = { 6a00 8d859cebffff 50 ff15???????? 50 8d859cebffff 50 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   8d859cebffff         | lea                 eax, [ebp - 0x1464]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d859cebffff         | lea                 eax, [ebp - 0x1464]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 360448
}