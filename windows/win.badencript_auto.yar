rule win_badencript_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.badencript."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badencript"
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
        $sequence_0 = { e9???????? c745e0b00f4100 e9???????? c745e0b80f4100 e9???????? c745e0a40f4100 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   c745e0b00f4100       | mov                 dword ptr [ebp - 0x20], 0x410fb0
            //   e9????????           |                     
            //   c745e0b80f4100       | mov                 dword ptr [ebp - 0x20], 0x410fb8
            //   e9????????           |                     
            //   c745e0a40f4100       | mov                 dword ptr [ebp - 0x20], 0x410fa4

        $sequence_1 = { 59 8bcf 83e73f c1f906 6bd730 8b0c8d48414100 c644112800 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8bcf                 | mov                 ecx, edi
            //   83e73f               | and                 edi, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bd730               | imul                edx, edi, 0x30
            //   8b0c8d48414100       | mov                 ecx, dword ptr [ecx*4 + 0x414148]
            //   c644112800           | mov                 byte ptr [ecx + edx + 0x28], 0

        $sequence_2 = { 03148d48414100 8b00 894218 8a03 }
            // n = 4, score = 100
            //   03148d48414100       | add                 edx, dword ptr [ecx*4 + 0x414148]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   894218               | mov                 dword ptr [edx + 0x18], eax
            //   8a03                 | mov                 al, byte ptr [ebx]

        $sequence_3 = { 83e03f 6bc830 8b049548414100 f644082801 7421 }
            // n = 5, score = 100
            //   83e03f               | and                 eax, 0x3f
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049548414100       | mov                 eax, dword ptr [edx*4 + 0x414148]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7421                 | je                  0x23

        $sequence_4 = { 6bc930 8b048548414100 f644082801 7406 8b440818 5d c3 }
            // n = 7, score = 100
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8b048548414100       | mov                 eax, dword ptr [eax*4 + 0x414148]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7406                 | je                  8
            //   8b440818             | mov                 eax, dword ptr [eax + ecx + 0x18]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_5 = { 8bc8 83e03f c1f906 6bc030 03048d48414100 50 }
            // n = 6, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e03f               | and                 eax, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bc030               | imul                eax, eax, 0x30
            //   03048d48414100       | add                 eax, dword ptr [ecx*4 + 0x414148]
            //   50                   | push                eax

        $sequence_6 = { 8bc1 83e13f c1f806 6bc930 8b048548414100 f644082801 }
            // n = 6, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   83e13f               | and                 ecx, 0x3f
            //   c1f806               | sar                 eax, 6
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8b048548414100       | mov                 eax, dword ptr [eax*4 + 0x414148]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1

        $sequence_7 = { ffd7 85c0 7518 50 68???????? 68???????? }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7518                 | jne                 0x1a
            //   50                   | push                eax
            //   68????????           |                     
            //   68????????           |                     

        $sequence_8 = { 53 56 57 8d1c85383d4100 33c0 f00fb10b }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d1c85383d4100       | lea                 ebx, [eax*4 + 0x413d38]
            //   33c0                 | xor                 eax, eax
            //   f00fb10b             | lock cmpxchg        dword ptr [ebx], ecx

        $sequence_9 = { 7420 6bc618 57 8db8183f4100 57 ff15???????? ff0d???????? }
            // n = 7, score = 100
            //   7420                 | je                  0x22
            //   6bc618               | imul                eax, esi, 0x18
            //   57                   | push                edi
            //   8db8183f4100         | lea                 edi, [eax + 0x413f18]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff0d????????         |                     

    condition:
        7 of them and filesize < 335872
}