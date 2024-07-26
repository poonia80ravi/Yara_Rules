rule win_qtbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.qtbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qtbot"
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
        $sequence_0 = { 889435fcfeffff 0fb68c1dfcfeffff 0fb6c2 03c8 8b450c }
            // n = 5, score = 200
            //   889435fcfeffff       | mov                 byte ptr [ebp + esi - 0x104], dl
            //   0fb68c1dfcfeffff     | movzx               ecx, byte ptr [ebp + ebx - 0x104]
            //   0fb6c2               | movzx               eax, dl
            //   03c8                 | add                 ecx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_1 = { 8b4510 89450c 8d4301 0fb6d8 8a941dfcfeffff 0fb6c2 }
            // n = 6, score = 200
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   8d4301               | lea                 eax, [ebx + 1]
            //   0fb6d8               | movzx               ebx, al
            //   8a941dfcfeffff       | mov                 dl, byte ptr [ebp + ebx - 0x104]
            //   0fb6c2               | movzx               eax, dl

        $sequence_2 = { 8b5508 33c0 53 8a1a }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   53                   | push                ebx
            //   8a1a                 | mov                 bl, byte ptr [edx]

        $sequence_3 = { 64a130000000 8b400c 8b7014 ad 8b00 }
            // n = 5, score = 200
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   8b7014               | mov                 esi, dword ptr [eax + 0x14]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_4 = { 8b450c 0fb6c9 8a8c0dfcfeffff 3008 40 89450c 83ef01 }
            // n = 7, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb6c9               | movzx               ecx, cl
            //   8a8c0dfcfeffff       | mov                 cl, byte ptr [ebp + ecx - 0x104]
            //   3008                 | xor                 byte ptr [eax], cl
            //   40                   | inc                 eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   83ef01               | sub                 edi, 1

        $sequence_5 = { 53 8a1a 6bc80d 0fb6c3 83c0d0 03c1 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   8a1a                 | mov                 bl, byte ptr [edx]
            //   6bc80d               | imul                ecx, eax, 0xd
            //   0fb6c3               | movzx               eax, bl
            //   83c0d0               | add                 eax, -0x30
            //   03c1                 | add                 eax, ecx

        $sequence_6 = { 8b049a 03c6 50 e8???????? 3b4508 740b }
            // n = 6, score = 200
            //   8b049a               | mov                 eax, dword ptr [edx + ebx*4]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]
            //   740b                 | je                  0xd

        $sequence_7 = { 85ff 7455 8b4510 89450c }
            // n = 4, score = 200
            //   85ff                 | test                edi, edi
            //   7455                 | je                  0x57
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax

        $sequence_8 = { ff15???????? 833e05 7521 6a10 6a40 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   833e05               | cmp                 dword ptr [esi], 5
            //   7521                 | jne                 0x23
            //   6a10                 | push                0x10
            //   6a40                 | push                0x40

        $sequence_9 = { 33db 83f855 0f872affffff 0fb6805a210010 ff2485f6200010 8b8614080000 }
            // n = 6, score = 100
            //   33db                 | xor                 ebx, ebx
            //   83f855               | cmp                 eax, 0x55
            //   0f872affffff         | ja                  0xffffff30
            //   0fb6805a210010       | movzx               eax, byte ptr [eax + 0x1000215a]
            //   ff2485f6200010       | jmp                 dword ptr [eax*4 + 0x100020f6]
            //   8b8614080000         | mov                 eax, dword ptr [esi + 0x814]

        $sequence_10 = { 0fb6805a210010 ff2485f6200010 8b8614080000 3b45f4 7e03 8945f4 8365fc00 }
            // n = 7, score = 100
            //   0fb6805a210010       | movzx               eax, byte ptr [eax + 0x1000215a]
            //   ff2485f6200010       | jmp                 dword ptr [eax*4 + 0x100020f6]
            //   8b8614080000         | mov                 eax, dword ptr [esi + 0x814]
            //   3b45f4               | cmp                 eax, dword ptr [ebp - 0xc]
            //   7e03                 | jle                 5
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

        $sequence_11 = { 7504 8b2f eb02 8bef 8b06 83661c00 }
            // n = 6, score = 100
            //   7504                 | jne                 6
            //   8b2f                 | mov                 ebp, dword ptr [edi]
            //   eb02                 | jmp                 4
            //   8bef                 | mov                 ebp, edi
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83661c00             | and                 dword ptr [esi + 0x1c], 0

        $sequence_12 = { 8b7df4 8b0c855c300010 c1e705 33d2 }
            // n = 4, score = 100
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   8b0c855c300010       | mov                 ecx, dword ptr [eax*4 + 0x1000305c]
            //   c1e705               | shl                 edi, 5
            //   33d2                 | xor                 edx, edx

        $sequence_13 = { 751e 837efcff 7518 8b46f8 8b04855c300010 c1e002 }
            // n = 6, score = 100
            //   751e                 | jne                 0x20
            //   837efcff             | cmp                 dword ptr [esi - 4], -1
            //   7518                 | jne                 0x1a
            //   8b46f8               | mov                 eax, dword ptr [esi - 8]
            //   8b04855c300010       | mov                 eax, dword ptr [eax*4 + 0x1000305c]
            //   c1e002               | shl                 eax, 2

        $sequence_14 = { 83f907 0f8781000000 ff248dfb240010 881f eb76 }
            // n = 5, score = 100
            //   83f907               | cmp                 ecx, 7
            //   0f8781000000         | ja                  0x87
            //   ff248dfb240010       | jmp                 dword ptr [ecx*4 + 0x100024fb]
            //   881f                 | mov                 byte ptr [edi], bl
            //   eb76                 | jmp                 0x78

        $sequence_15 = { e8???????? 59 837e04ff 8bd8 8d7e08 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   837e04ff             | cmp                 dword ptr [esi + 4], -1
            //   8bd8                 | mov                 ebx, eax
            //   8d7e08               | lea                 edi, [esi + 8]

    condition:
        7 of them and filesize < 57344
}