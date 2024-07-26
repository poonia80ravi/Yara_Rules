rule win_mulcom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mulcom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mulcom"
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
        $sequence_0 = { 33db 8bf3 895d8f 895d87 48395a10 0f8445030000 49395810 }
            // n = 7, score = 100
            //   33db                 | mov                 ecx, ebx
            //   8bf3                 | dec                 eax
            //   895d8f               | mov                 edx, ebx
            //   895d87               | dec                 eax
            //   48395a10             | mov                 ecx, edi
            //   0f8445030000         | dec                 eax
            //   49395810             | and                 dword ptr [esi + 0x10], 0

        $sequence_1 = { 8901 488b4b40 488b11 488d4202 488901 498d4002 6644893a }
            // n = 7, score = 100
            //   8901                 | dec                 eax
            //   488b4b40             | mov                 dword ptr [ebx + 0x80], eax
            //   488b11               | dec                 eax
            //   488d4202             | cmp                 dword ptr [ebx + 0x78], edi
            //   488901               | je                  0x2eb
            //   498d4002             | dec                 eax
            //   6644893a             | test                eax, eax

        $sequence_2 = { 488b4c1948 488b01 4d8bc6 498bd4 ff5048 493bc6 74ae }
            // n = 7, score = 100
            //   488b4c1948           | mov                 dword ptr [esp + 0x20], ebx
            //   488b01               | inc                 esp
            //   4d8bc6               | mov                 bh, byte ptr [esp + 0x30]
            //   498bd4               | dec                 esp
            //   ff5048               | lea                 ecx, [ebp - 0x39]
            //   493bc6               | dec                 eax
            //   74ae                 | cmp                 dword ptr [ebp - 0x21], 0x10

        $sequence_3 = { 0f84ca030000 4489442430 4c8d0d1c290400 4c89442428 488d15202a0400 4c89442420 488bc8 }
            // n = 7, score = 100
            //   0f84ca030000         | jbe                 0x14e
            //   4489442430           | dec                 eax
            //   4c8d0d1c290400       | mov                 eax, edx
            //   4c89442428           | dec                 eax
            //   488d15202a0400       | shr                 eax, 0x3f
            //   4c89442420           | dec                 eax
            //   488bc8               | add                 edx, eax

        $sequence_4 = { 4d8958f8 498918 66458958e8 4f895c0118 4f895c0120 410f104008 4d8d8088000000 }
            // n = 7, score = 100
            //   4d8958f8             | dec                 eax
            //   498918               | lea                 eax, [edi + ebx*4]
            //   66458958e8           | dec                 eax
            //   4f895c0118           | mov                 ebx, dword ptr [esp + 0x40]
            //   4f895c0120           | dec                 eax
            //   410f104008           | mov                 ebp, dword ptr [esp + 0x48]
            //   4d8d8088000000       | dec                 eax

        $sequence_5 = { 48894008 4883a6e000000000 483b8ed8000000 7419 488b19 ba18000000 }
            // n = 6, score = 100
            //   48894008             | test                ebx, ebx
            //   4883a6e000000000     | je                  0x28b
            //   483b8ed8000000       | inc                 ecx
            //   7419                 | mov                 eax, dword ptr [esi]
            //   488b19               | lea                 ecx, [eax + ebx]
            //   ba18000000           | inc                 ecx

        $sequence_6 = { 83030c e8???????? eb13 8364242000 4533c9 4533c0 488bcf }
            // n = 7, score = 100
            //   83030c               | dec                 eax
            //   e8????????           |                     
            //   eb13                 | mov                 ebp, dword ptr [esp + 0x58]
            //   8364242000           | dec                 eax
            //   4533c9               | mov                 esi, dword ptr [esp + 0x60]
            //   4533c0               | jne                 0x37a
            //   488bcf               | mov                 byte ptr [esp + 0x73], 3

        $sequence_7 = { 493bde 75d0 488b1e 488b4e10 482bcb 48b87978787878787878 48f7e9 }
            // n = 7, score = 100
            //   493bde               | inc                 ecx
            //   75d0                 | mov                 bh, ch
            //   488b1e               | mov                 ecx, dword ptr [ecx + 0x60]
            //   488b4e10             | test                ecx, ecx
            //   482bcb               | je                  0xaa7
            //   48b87978787878787878     | xor    edx, edx
            //   48f7e9               | dec                 eax

        $sequence_8 = { e9???????? 488d8a98000000 e9???????? 488d8a28000000 e9???????? 4889542410 55 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488d8a98000000       | xor                 eax, eax
            //   e9????????           |                     
            //   488d8a28000000       | inc                 ecx
            //   e9????????           |                     
            //   4889542410           | mov                 edx, esi
            //   55                   | dec                 eax

        $sequence_9 = { 488bcb e8???????? 90 488d4c2428 e8???????? 32c0 488b4c2448 }
            // n = 7, score = 100
            //   488bcb               | movdqa              xmmword ptr [ebp + 0x140], xmm0
            //   e8????????           |                     
            //   90                   | mov                 byte ptr [ebp + 0x130], bl
            //   488d4c2428           | movdqa              xmm1, xmm0
            //   e8????????           |                     
            //   32c0                 | movdqa              xmmword ptr [ebp + 0x160], xmm0
            //   488b4c2448           | mov                 byte ptr [ebp + 0x150], bl

    condition:
        7 of them and filesize < 867328
}