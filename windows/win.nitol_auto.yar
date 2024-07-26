rule win_nitol_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.nitol."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitol"
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
        $sequence_0 = { 8b45f8 817de8bb010000 a3???????? 8d8568ffffff 50 }
            // n = 5, score = 200
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   817de8bb010000       | cmp                 dword ptr [ebp - 0x18], 0x1bb
            //   a3????????           |                     
            //   8d8568ffffff         | lea                 eax, [ebp - 0x98]
            //   50                   | push                eax

        $sequence_1 = { 33ed 39be88000000 0f8e10040000 57 57 56 68???????? }
            // n = 7, score = 200
            //   33ed                 | xor                 ebp, ebp
            //   39be88000000         | cmp                 dword ptr [esi + 0x88], edi
            //   0f8e10040000         | jle                 0x416
            //   57                   | push                edi
            //   57                   | push                edi
            //   56                   | push                esi
            //   68????????           |                     

        $sequence_2 = { 53 53 53 8d8514faffff 53 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d8514faffff         | lea                 eax, [ebp - 0x5ec]
            //   53                   | push                ebx

        $sequence_3 = { 53 50 e8???????? 83c444 8d8558ffffff 6a28 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c444               | add                 esp, 0x44
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   6a28                 | push                0x28

        $sequence_4 = { 50 ff35???????? e8???????? 59 8b35???????? 59 bf64040000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff35????????         |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b35????????         |                     
            //   59                   | pop                 ecx
            //   bf64040000           | mov                 edi, 0x464

        $sequence_5 = { 8d45d8 6a14 50 8d854cffffff 50 e8???????? 8d8540ffffff }
            // n = 7, score = 200
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   6a14                 | push                0x14
            //   50                   | push                eax
            //   8d854cffffff         | lea                 eax, [ebp - 0xb4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8540ffffff         | lea                 eax, [ebp - 0xc0]

        $sequence_6 = { e8???????? 837dec00 75a9 837de800 7585 837de400 0f855bffffff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0
            //   75a9                 | jne                 0xffffffab
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   7585                 | jne                 0xffffff87
            //   837de400             | cmp                 dword ptr [ebp - 0x1c], 0
            //   0f855bffffff         | jne                 0xffffff61

        $sequence_7 = { 66c745f80200 66895df6 66c745fa0002 c645f408 ff15???????? 8945fc 8d45f4 }
            // n = 7, score = 200
            //   66c745f80200         | mov                 word ptr [ebp - 8], 2
            //   66895df6             | mov                 word ptr [ebp - 0xa], bx
            //   66c745fa0002         | mov                 word ptr [ebp - 6], 0x200
            //   c645f408             | mov                 byte ptr [ebp - 0xc], 8
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_8 = { 53 ff15???????? 8b35???????? 6840771b00 ffd6 53 ff15???????? }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   6840771b00           | push                0x1b7740
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_9 = { ff15???????? 53 8d8df8fcffff 6a0a }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   8d8df8fcffff         | lea                 ecx, [ebp - 0x308]
            //   6a0a                 | push                0xa

    condition:
        7 of them and filesize < 139264
}