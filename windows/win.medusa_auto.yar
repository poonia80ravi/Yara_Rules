rule win_medusa_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.medusa."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusa"
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
        $sequence_0 = { f8 7e0b c786381bb8a842314a64 27 98 76cb 4e }
            // n = 7, score = 100
            //   f8                   | clc                 
            //   7e0b                 | jle                 0xd
            //   c786381bb8a842314a64     | mov    dword ptr [esi - 0x5747e4c8], 0x644a3142
            //   27                   | daa                 
            //   98                   | cwde                
            //   76cb                 | jbe                 0xffffffcd
            //   4e                   | dec                 esi

        $sequence_1 = { 7bbc 45 030479 99 5f 68066e570a }
            // n = 6, score = 100
            //   7bbc                 | jnp                 0xffffffbe
            //   45                   | inc                 ebp
            //   030479               | add                 eax, dword ptr [ecx + edi*2]
            //   99                   | cdq                 
            //   5f                   | pop                 edi
            //   68066e570a           | push                0xa576e06

        $sequence_2 = { a8cf f8 7e0b c786381bb8a842314a64 27 98 76cb }
            // n = 7, score = 100
            //   a8cf                 | test                al, 0xcf
            //   f8                   | clc                 
            //   7e0b                 | jle                 0xd
            //   c786381bb8a842314a64     | mov    dword ptr [esi - 0x5747e4c8], 0x644a3142
            //   27                   | daa                 
            //   98                   | cwde                
            //   76cb                 | jbe                 0xffffffcd

        $sequence_3 = { bd0ab2825a 4e 9f c48b2addd977 7612 a5 }
            // n = 6, score = 100
            //   bd0ab2825a           | mov                 ebp, 0x5a82b20a
            //   4e                   | dec                 esi
            //   9f                   | lahf                
            //   c48b2addd977         | les                 ecx, ptr [ebx + 0x77d9dd2a]
            //   7612                 | jbe                 0x14
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_4 = { 99 5f 68066e570a 4f bfdb4a7adc de6326 }
            // n = 6, score = 100
            //   99                   | cdq                 
            //   5f                   | pop                 edi
            //   68066e570a           | push                0xa576e06
            //   4f                   | dec                 edi
            //   bfdb4a7adc           | mov                 edi, 0xdc7a4adb
            //   de6326               | fisub               word ptr [ebx + 0x26]

        $sequence_5 = { aa 97 691c85470859bab566c1a5 8d39 b4e9 }
            // n = 5, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   97                   | xchg                eax, edi
            //   691c85470859bab566c1a5     | imul    ebx, dword ptr [eax*4 - 0x45a6f7b9], 0xa5c166b5
            //   8d39                 | lea                 edi, [ecx]
            //   b4e9                 | mov                 ah, 0xe9

        $sequence_6 = { 1a03 69c421f3ef6a 2048b3 a5 45 b051 }
            // n = 6, score = 100
            //   1a03                 | sbb                 al, byte ptr [ebx]
            //   69c421f3ef6a         | imul                eax, esp, 0x6aeff321
            //   2048b3               | and                 byte ptr [eax - 0x4d], cl
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   45                   | inc                 ebp
            //   b051                 | mov                 al, 0x51

        $sequence_7 = { 4f bfdb4a7adc de6326 9e 45 334a54 }
            // n = 6, score = 100
            //   4f                   | dec                 edi
            //   bfdb4a7adc           | mov                 edi, 0xdc7a4adb
            //   de6326               | fisub               word ptr [ebx + 0x26]
            //   9e                   | sahf                
            //   45                   | inc                 ebp
            //   334a54               | xor                 ecx, dword ptr [edx + 0x54]

        $sequence_8 = { 691c85470859bab566c1a5 8d39 b4e9 c53415dc593229 0450 1a03 69c421f3ef6a }
            // n = 7, score = 100
            //   691c85470859bab566c1a5     | imul    ebx, dword ptr [eax*4 - 0x45a6f7b9], 0xa5c166b5
            //   8d39                 | lea                 edi, [ecx]
            //   b4e9                 | mov                 ah, 0xe9
            //   c53415dc593229       | lds                 esi, ptr [edx + 0x293259dc]
            //   0450                 | add                 al, 0x50
            //   1a03                 | sbb                 al, byte ptr [ebx]
            //   69c421f3ef6a         | imul                eax, esp, 0x6aeff321

        $sequence_9 = { a8cf f8 7e0b c786381bb8a842314a64 }
            // n = 4, score = 100
            //   a8cf                 | test                al, 0xcf
            //   f8                   | clc                 
            //   7e0b                 | jle                 0xd
            //   c786381bb8a842314a64     | mov    dword ptr [esi - 0x5747e4c8], 0x644a3142

    condition:
        7 of them and filesize < 1589248
}