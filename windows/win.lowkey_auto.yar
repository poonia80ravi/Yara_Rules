rule win_lowkey_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.lowkey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowkey"
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
        $sequence_0 = { 488d4d30 4533c0 baa00f0000 e8???????? 488b05???????? 488d1579f30300 488bcb }
            // n = 7, score = 100
            //   488d4d30             | lea                 eax, [0x155c7]
            //   4533c0               | jmp                 0x300
            //   baa00f0000           | mov                 edi, edx
            //   e8????????           |                     
            //   488b05????????       |                     
            //   488d1579f30300       | dec                 eax
            //   488bcb               | mov                 esi, ecx

        $sequence_1 = { 33d2 488bc8 ff15???????? 488d1556260200 488d8d70010000 ff15???????? 85c0 }
            // n = 7, score = 100
            //   33d2                 | mov                 ecx, dword ptr [esp + 0x30]
            //   488bc8               | inc                 esp
            //   ff15????????         |                     
            //   488d1556260200       | lea                 ecx, [ebx + 0x10]
            //   488d8d70010000       | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | mov                 dword ptr [esp + 0x28], ebx

        $sequence_2 = { ffc1 32d2 ffc7 460fb60437 4584c0 0f8576ffffff }
            // n = 6, score = 100
            //   ffc1                 | sub                 esp, 0x2b0
            //   32d2                 | dec                 eax
            //   ffc7                 | xor                 eax, esp
            //   460fb60437           | dec                 eax
            //   4584c0               | mov                 dword ptr [esp + 0x2a8], eax
            //   0f8576ffffff         | dec                 eax

        $sequence_3 = { 4889742468 488d5928 4c89742428 4c8bf2 4963e8 488bf1 4885db }
            // n = 7, score = 100
            //   4889742468           | mov                 edx, ebp
            //   488d5928             | dec                 ecx
            //   4c89742428           | mov                 ecx, esi
            //   4c8bf2               | mov                 dword ptr [esp + 0x40], ebx
            //   4963e8               | dec                 eax
            //   488bf1               | mov                 esi, eax
            //   4885db               | dec                 eax

        $sequence_4 = { 4533c0 488d542428 e8???????? 85c0 400f95c7 8bc7 eb05 }
            // n = 7, score = 100
            //   4533c0               | jne                 0xd1a
            //   488d542428           | inc                 ebp
            //   e8????????           |                     
            //   85c0                 | mov                 edi, esi
            //   400f95c7             | inc                 esp
            //   8bc7                 | mov                 dword ptr [ebp + 0x150], esi
            //   eb05                 | dec                 eax

        $sequence_5 = { 8b461c 3b4620 0f94c0 884608 }
            // n = 4, score = 100
            //   8b461c               | dec                 eax
            //   3b4620               | mov                 ecx, ebx
            //   0f94c0               | dec                 eax
            //   884608               | lea                 edx, [esp + 0x50]

        $sequence_6 = { b900001000 e8???????? 48894310 66c743080100 897378 48891d???????? b902020000 }
            // n = 7, score = 100
            //   b900001000           | dec                 esp
            //   e8????????           |                     
            //   48894310             | mov                 esi, eax
            //   66c743080100         | inc                 ebp
            //   897378               | lea                 eax, [ecx + 1]
            //   48891d????????       |                     
            //   b902020000           | dec                 eax

        $sequence_7 = { 8d78ff 488d0543fbfeff 0fb68cb892ed0100 0fb6b4b893ed0100 8bd9 48c1e302 4c8bc3 }
            // n = 7, score = 100
            //   8d78ff               | dec                 eax
            //   488d0543fbfeff       | mov                 ecx, eax
            //   0fb68cb892ed0100     | dec                 eax
            //   0fb6b4b893ed0100     | add                 ecx, dword ptr [esi + 0x10]
            //   8bd9                 | inc                 esp
            //   48c1e302             | sub                 edi, eax
            //   4c8bc3               | inc                 esp

        $sequence_8 = { 488bd0 488bcb ff15???????? 85c0 741e 488bd6 488bcb }
            // n = 7, score = 100
            //   488bd0               | mov                 eax, 0x65
            //   488bcb               | mov                 word ptr [esp + 0x35], ax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741e                 | test                eax, eax
            //   488bd6               | je                  0x32a
            //   488bcb               | mov                 eax, 1

        $sequence_9 = { 488d4c2470 4c89ac24c0210000 ff15???????? 488b4b10 e8???????? 448be8 }
            // n = 6, score = 100
            //   488d4c2470           | dec                 eax
            //   4c89ac24c0210000     | mov                 ecx, esi
            //   ff15????????         |                     
            //   488b4b10             | dec                 esp
            //   e8????????           |                     
            //   448be8               | mov                 ebp, dword ptr [esp + 0x47a8]

    condition:
        7 of them and filesize < 643072
}