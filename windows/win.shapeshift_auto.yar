rule win_shapeshift_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.shapeshift."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shapeshift"
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
        $sequence_0 = { 50 6af6 ff15???????? 8b04bd38054200 834c0318ff 33c0 eb16 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6af6                 | push                -0xa
            //   ff15????????         |                     
            //   8b04bd38054200       | mov                 eax, dword ptr [edi*4 + 0x420538]
            //   834c0318ff           | or                  dword ptr [ebx + eax + 0x18], 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   eb16                 | jmp                 0x18

        $sequence_1 = { 57 e8???????? 8b442424 4e 40 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   4e                   | dec                 esi
            //   40                   | inc                 eax

        $sequence_2 = { 0fbf0d???????? 0fb689589a4100 884b02 0fbf05???????? }
            // n = 4, score = 100
            //   0fbf0d????????       |                     
            //   0fb689589a4100       | movzx               ecx, byte ptr [ecx + 0x419a58]
            //   884b02               | mov                 byte ptr [ebx + 2], cl
            //   0fbf05????????       |                     

        $sequence_3 = { 6a00 ff15???????? eb22 81fe11010000 7525 6683ff01 7406 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   eb22                 | jmp                 0x24
            //   81fe11010000         | cmp                 esi, 0x111
            //   7525                 | jne                 0x27
            //   6683ff01             | cmp                 di, 1
            //   7406                 | je                  8

        $sequence_4 = { e8???????? 83c404 8b35???????? b8afa96e5e }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b35????????         |                     
            //   b8afa96e5e           | mov                 eax, 0x5e6ea9af

        $sequence_5 = { 8b95a0fdffff 8bcf e8???????? 83c404 ff750c ff15???????? 6a02 }
            // n = 7, score = 100
            //   8b95a0fdffff         | mov                 edx, dword ptr [ebp - 0x260]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     
            //   6a02                 | push                2

        $sequence_6 = { a1???????? 33c5 50 8d45f4 64a300000000 eb24 8b048dc4fc4100 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   eb24                 | jmp                 0x26
            //   8b048dc4fc4100       | mov                 eax, dword ptr [ecx*4 + 0x41fcc4]

        $sequence_7 = { c745e04c804100 e9???????? c745dc02000000 c745e04c804100 8b4508 }
            // n = 5, score = 100
            //   c745e04c804100       | mov                 dword ptr [ebp - 0x20], 0x41804c
            //   e9????????           |                     
            //   c745dc02000000       | mov                 dword ptr [ebp - 0x24], 2
            //   c745e04c804100       | mov                 dword ptr [ebp - 0x20], 0x41804c
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 303104
}