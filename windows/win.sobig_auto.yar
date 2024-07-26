rule win_sobig_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.sobig."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sobig"
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
        $sequence_0 = { 50 e8???????? 51 8bcc 896508 68???????? e8???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   51                   | push                ecx
            //   8bcc                 | mov                 ecx, esp
            //   896508               | mov                 dword ptr [ebp + 8], esp
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_1 = { 8b4e30 8d7e30 834de0ff 6683e100 0fb7c0 0bc8 }
            // n = 6, score = 100
            //   8b4e30               | mov                 ecx, dword ptr [esi + 0x30]
            //   8d7e30               | lea                 edi, [esi + 0x30]
            //   834de0ff             | or                  dword ptr [ebp - 0x20], 0xffffffff
            //   6683e100             | and                 cx, 0
            //   0fb7c0               | movzx               eax, ax
            //   0bc8                 | or                  ecx, eax

        $sequence_2 = { c9 c20400 f605????????01 7507 800d????????01 e8???????? f605????????01 }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   f605????????01       |                     
            //   7507                 | jne                 9
            //   800d????????01       |                     
            //   e8????????           |                     
            //   f605????????01       |                     

        $sequence_3 = { 889de3faffff 50 e8???????? 8b7f04 59 3bfb }
            // n = 6, score = 100
            //   889de3faffff         | mov                 byte ptr [ebp - 0x51d], bl
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7f04               | mov                 edi, dword ptr [edi + 4]
            //   59                   | pop                 ecx
            //   3bfb                 | cmp                 edi, ebx

        $sequence_4 = { 59 8975e8 7403 802600 68???????? 57 e8???????? }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   7403                 | je                  5
            //   802600               | and                 byte ptr [esi], 0
            //   68????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_5 = { 8b4608 51 8d4d08 48 51 50 8bce }
            // n = 7, score = 100
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   51                   | push                ecx
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   48                   | dec                 eax
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi

        $sequence_6 = { 741a ff750c e8???????? 668945f2 8d45f0 6a10 50 }
            // n = 7, score = 100
            //   741a                 | je                  0x1c
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   668945f2             | mov                 word ptr [ebp - 0xe], ax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   6a10                 | push                0x10
            //   50                   | push                eax

        $sequence_7 = { 50 56 ff15???????? 85c0 7410 ff75dc 8b3d???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   8b3d????????         |                     

        $sequence_8 = { e8???????? c645fc08 e8???????? 8bf8 57 e8???????? 59 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_9 = { 56 50 ff7508 c645fc01 e8???????? 83c40c 8d4de0 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4de0               | lea                 ecx, [ebp - 0x20]

    condition:
        7 of them and filesize < 262144
}