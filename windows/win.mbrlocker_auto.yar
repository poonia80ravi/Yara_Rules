rule win_mbrlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.mbrlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mbrlocker"
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
        $sequence_0 = { 50 8b35???????? 8b3d???????? 6a10 68???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8b35????????         |                     
            //   8b3d????????         |                     
            //   6a10                 | push                0x10
            //   68????????           |                     

        $sequence_1 = { 68fe000000 68???????? ffd7 83c408 }
            // n = 4, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   83c408               | add                 esp, 8

        $sequence_2 = { 68ac000000 68???????? e8???????? 68ac000000 68???????? ffd7 83c408 }
            // n = 7, score = 100
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   e8????????           |                     
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   83c408               | add                 esp, 8

        $sequence_3 = { c705????????ba514000 c705????????00020000 68fe000000 68???????? ffd6 83c408 68ff000000 }
            // n = 7, score = 100
            //   c705????????ba514000     |     
            //   c705????????00020000     |     
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c408               | add                 esp, 8
            //   68ff000000           | push                0xff

        $sequence_4 = { 68ac000000 68???????? e8???????? e8???????? }
            // n = 4, score = 100
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_5 = { 68ff000000 68ac000000 68???????? e8???????? e8???????? 68ff000000 68ac000000 }
            // n = 7, score = 100
            //   68ff000000           | push                0xff
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   68ff000000           | push                0xff
            //   68ac000000           | push                0xac

        $sequence_6 = { ac 30c8 aa 4a 75f9 61 c9 }
            // n = 7, score = 100
            //   ac                   | lodsb               al, byte ptr [esi]
            //   30c8                 | xor                 al, cl
            //   aa                   | stosb               byte ptr es:[edi], al
            //   4a                   | dec                 edx
            //   75f9                 | jne                 0xfffffffb
            //   61                   | popal               
            //   c9                   | leave               

        $sequence_7 = { 68fe000000 68???????? e8???????? 68fe000000 }
            // n = 4, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   e8????????           |                     
            //   68fe000000           | push                0xfe

        $sequence_8 = { 68fe000000 68???????? e8???????? e8???????? 68ff000000 68fe000000 }
            // n = 6, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   68ff000000           | push                0xff
            //   68fe000000           | push                0xfe

        $sequence_9 = { 31c8 e8???????? 68ac000000 68???????? }
            // n = 4, score = 100
            //   31c8                 | xor                 eax, ecx
            //   e8????????           |                     
            //   68ac000000           | push                0xac
            //   68????????           |                     

    condition:
        7 of them and filesize < 43008
}