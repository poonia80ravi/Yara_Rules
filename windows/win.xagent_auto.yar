rule win_xagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.xagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xagent"
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
        $sequence_0 = { c1ea02 6bd20d b801000000 2bc2 }
            // n = 4, score = 3100
            //   c1ea02               | shr                 edx, 2
            //   6bd20d               | imul                edx, edx, 0xd
            //   b801000000           | mov                 eax, 1
            //   2bc2                 | sub                 eax, edx

        $sequence_1 = { ff15???????? 8bd8 e8???????? 03d8 }
            // n = 4, score = 3100
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   03d8                 | add                 ebx, eax

        $sequence_2 = { 8b4604 85c0 7407 8b4d08 8b11 8910 83460404 }
            // n = 7, score = 2600
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8910                 | mov                 dword ptr [eax], edx
            //   83460404             | add                 dword ptr [esi + 4], 4

        $sequence_3 = { 8bc1 57 8b7a08 c1e802 }
            // n = 4, score = 2600
            //   8bc1                 | mov                 eax, ecx
            //   57                   | push                edi
            //   8b7a08               | mov                 edi, dword ptr [edx + 8]
            //   c1e802               | shr                 eax, 2

        $sequence_4 = { 3b7e0c 7707 c7460c00000000 49 894e10 }
            // n = 5, score = 2600
            //   3b7e0c               | cmp                 edi, dword ptr [esi + 0xc]
            //   7707                 | ja                  9
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0
            //   49                   | dec                 ecx
            //   894e10               | mov                 dword ptr [esi + 0x10], ecx

        $sequence_5 = { c20400 8d4de4 e8???????? b8???????? }
            // n = 4, score = 2600
            //   c20400               | ret                 4
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   b8????????           |                     

        $sequence_6 = { 8b00 6a00 50 68???????? 6a00 }
            // n = 5, score = 2600
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_7 = { 49 894e10 7507 c7460c00000000 5f }
            // n = 5, score = 2600
            //   49                   | dec                 ecx
            //   894e10               | mov                 dword ptr [esi + 0x10], ecx
            //   7507                 | jne                 9
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0
            //   5f                   | pop                 edi

        $sequence_8 = { 55 8bec 33c0 83ec0c 39412c }
            // n = 5, score = 2600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   33c0                 | xor                 eax, eax
            //   83ec0c               | sub                 esp, 0xc
            //   39412c               | cmp                 dword ptr [ecx + 0x2c], eax

        $sequence_9 = { 8b4e10 85c9 7423 8b7e08 ff460c }
            // n = 5, score = 2600
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   85c9                 | test                ecx, ecx
            //   7423                 | je                  0x25
            //   8b7e08               | mov                 edi, dword ptr [esi + 8]
            //   ff460c               | inc                 dword ptr [esi + 0xc]

        $sequence_10 = { 8bd8 e8???????? 8d0c18 e8???????? }
            // n = 4, score = 1500
            //   8bd8                 | mov                 eax, dword ptr [ebx + 0x28]
            //   e8????????           |                     
            //   8d0c18               | dec                 esp
            //   e8????????           |                     

        $sequence_11 = { e8???????? 488d542458 488bcb e8???????? 90 }
            // n = 5, score = 1500
            //   e8????????           |                     
            //   488d542458           | lea                 eax, [edi + esi]
            //   488bcb               | dec                 eax
            //   e8????????           |                     
            //   90                   | sub                 ecx, edi

        $sequence_12 = { e8???????? 498bce 4e8d0437 482bcf }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   498bce               | dec                 ecx
            //   4e8d0437             | mov                 ecx, esi
            //   482bcf               | dec                 esi

        $sequence_13 = { e8???????? 488b4328 4c8bcf 4c8bc6 }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   488b4328             | dec                 eax
            //   4c8bcf               | lea                 edx, [esp + 0x58]
            //   4c8bc6               | dec                 eax

        $sequence_14 = { 4053 4883ec20 488b5910 4885db 7416 }
            // n = 5, score = 1500
            //   4053                 | sub                 eax, ebp
            //   4883ec20             | dec                 ecx
            //   488b5910             | mov                 edx, ebp
            //   4885db               | dec                 eax
            //   7416                 | mov                 ecx, ebx

        $sequence_15 = { e8???????? 90 0fb705???????? 6689442420 }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   90                   | nop                 
            //   0fb705????????       |                     
            //   6689442420           | mov                 word ptr [esp + 0x20], ax

        $sequence_16 = { e8???????? 48833b00 740a 488b4308 }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   48833b00             | mov                 ecx, ebx
            //   740a                 | nop                 
            //   488b4308             | dec                 eax

        $sequence_17 = { ff15???????? baf4010000 488bcb ff15???????? }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   baf4010000           | cmp                 al, 1
            //   488bcb               | jne                 6
            //   ff15????????         |                     

        $sequence_18 = { b803b57ea5 f7e6 c1ea06 6bd263 }
            // n = 4, score = 500
            //   b803b57ea5           | mov                 al, 1
            //   f7e6                 | jmp                 6
            //   c1ea06               | xor                 al, al
            //   6bd263               | cmp                 al, 1

        $sequence_19 = { c1ea07 69d295000000 2bca 8bd1 }
            // n = 4, score = 400
            //   c1ea07               | mov                 al, 1
            //   69d295000000         | jmp                 4
            //   2bca                 | xor                 al, al
            //   8bd1                 | cmp                 al, 1

        $sequence_20 = { 75f7 4d2bc6 488bc3 4885db }
            // n = 4, score = 200
            //   75f7                 | cmp                 byte ptr [edi], 0
            //   4d2bc6               | dec                 esp
            //   488bc3               | mov                 eax, edi
            //   4885db               | jne                 0xfffffff9

        $sequence_21 = { 75f7 4d2bc6 803b00 488bc3 }
            // n = 4, score = 200
            //   75f7                 | mov                 eax, ebx
            //   4d2bc6               | dec                 eax
            //   803b00               | test                ebx, ebx
            //   488bc3               | jne                 0xfffffff9

        $sequence_22 = { 75f7 4d2bc6 498bd6 488bc8 }
            // n = 4, score = 200
            //   75f7                 | dec                 eax
            //   4d2bc6               | mov                 ecx, ebx
            //   498bd6               | dec                 esp
            //   488bc8               | mov                 eax, esi

        $sequence_23 = { 75f7 4d2bc5 498bd5 488bcb e8???????? 4c8bc6 }
            // n = 6, score = 200
            //   75f7                 | mov                 edx, 0x1f4
            //   4d2bc5               | dec                 eax
            //   498bd5               | mov                 ecx, ebx
            //   488bcb               | test                eax, eax
            //   e8????????           |                     
            //   4c8bc6               | jne                 0xfffffff9

        $sequence_24 = { 75f7 4d2bc5 498bd5 488bc8 e8???????? 803f00 4c8bc7 }
            // n = 7, score = 200
            //   75f7                 | dec                 eax
            //   4d2bc5               | mov                 ecx, ebx
            //   498bd5               | mov                 eax, 0xa57eb503
            //   488bc8               | mul                 esi
            //   e8????????           |                     
            //   803f00               | shr                 edx, 6
            //   4c8bc7               | imul                edx, edx, 0x63

    condition:
        7 of them and filesize < 729088
}