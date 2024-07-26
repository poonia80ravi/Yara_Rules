rule win_clambling_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.clambling."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clambling"
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
        $sequence_0 = { ba04010000 ff15???????? 413bc6 7506 }
            // n = 4, score = 300
            //   ba04010000           | je                  0x16f3
            //   ff15????????         |                     
            //   413bc6               | dec                 esp
            //   7506                 | mov                 dword ptr [esp + 0x38], edi

        $sequence_1 = { eb08 ff15???????? 8bd8 488b4c2458 }
            // n = 4, score = 300
            //   eb08                 | inc                 edx
            //   ff15????????         |                     
            //   8bd8                 | mov                 al, byte ptr [eax + eax]
            //   488b4c2458           | inc                 ecx

        $sequence_2 = { ff15???????? 493bdc 7409 488bcb ff15???????? }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   493bdc               | mov                 dword ptr [esp + 0x40], 0x40cc0020
            //   7409                 | mov                 ebx, edx
            //   488bcb               | cmp                 eax, edx
            //   ff15????????         |                     

        $sequence_3 = { ff15???????? 488905???????? 483bc6 7504 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   488905????????       |                     
            //   483bc6               | lea                 ecx, [edi + 0x14]
            //   7504                 | mov                 dword ptr [esp + 0x20], eax

        $sequence_4 = { 488bc8 4889742420 ff15???????? 488bcb }
            // n = 4, score = 300
            //   488bc8               | cmp                 eax, edi
            //   4889742420           | jne                 0xb3e
            //   ff15????????         |                     
            //   488bcb               | dec                 eax

        $sequence_5 = { ff15???????? 83f8ff 7524 ff15???????? 418bd7 488bcf 8bd8 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   83f8ff               | inc                 dx
            //   7524                 | mov                 dword ptr [edx + eax*2], edi
            //   ff15????????         |                     
            //   418bd7               | inc                 esp
            //   488bcf               | cmp                 eax, edi
            //   8bd8                 | dec                 esp

        $sequence_6 = { 498d53e8 418d4802 498943f0 ff15???????? 85c0 }
            // n = 5, score = 300
            //   498d53e8             | inc                 ecx
            //   418d4802             | push                edi
            //   498943f0             | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | sub                 esp, 0x40

        $sequence_7 = { 33d2 41b806020000 664489642420 e8???????? }
            // n = 4, score = 300
            //   33d2                 | arpl                ax, di
            //   41b806020000         | dec                 eax
            //   664489642420         | cmp                 dword ptr [ecx + edi*8 + 0x18], 0
            //   e8????????           |                     

        $sequence_8 = { e9???????? 6603db 8bf1 894c2438 }
            // n = 4, score = 300
            //   e9????????           |                     
            //   6603db               | dec                 eax
            //   8bf1                 | lea                 edx, [0x1af75]
            //   894c2438             | dec                 eax

        $sequence_9 = { 488bcb ff5030 4c8b1b ba01000000 488bcb }
            // n = 5, score = 300
            //   488bcb               | mov                 dword ptr [esi + 8], esp
            //   ff5030               | mov                 dword ptr [esi], eax
            //   4c8b1b               | mov                 dword ptr [esi + 4], 0x305
            //   ba01000000           | mov                 dword ptr [esi + 8], 0x420
            //   488bcb               | mov                 dword ptr [esi], eax

    condition:
        7 of them and filesize < 412672
}