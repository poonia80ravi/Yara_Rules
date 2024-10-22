rule win_vflooder_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.vflooder."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vflooder"
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
        $sequence_0 = { 9c 60 9c 9c 8d642430 }
            // n = 5, score = 400
            //   9c                   | pushfd              
            //   60                   | pushal              
            //   9c                   | pushfd              
            //   9c                   | pushfd              
            //   8d642430             | lea                 esp, [esp + 0x30]

        $sequence_1 = { e8???????? 0000 43 7265 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   0000                 | add                 byte ptr [eax], al
            //   43                   | inc                 ebx
            //   7265                 | jb                  0x67

        $sequence_2 = { 9c ff742404 8f4500 9c }
            // n = 4, score = 400
            //   9c                   | pushfd              
            //   ff742404             | push                dword ptr [esp + 4]
            //   8f4500               | pop                 dword ptr [ebp]
            //   9c                   | pushfd              

        $sequence_3 = { e8???????? 0000 43 7265 61 7465 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   0000                 | add                 byte ptr [eax], al
            //   43                   | inc                 ebx
            //   7265                 | jb                  0x67
            //   61                   | popal               
            //   7465                 | je                  0x67

        $sequence_4 = { 0000 43 7265 61 7465 }
            // n = 5, score = 400
            //   0000                 | add                 byte ptr [eax], al
            //   43                   | inc                 ebx
            //   7265                 | jb                  0x67
            //   61                   | popal               
            //   7465                 | je                  0x67

        $sequence_5 = { 9c ff742404 8f4500 9c 60 }
            // n = 5, score = 400
            //   9c                   | pushfd              
            //   ff742404             | push                dword ptr [esp + 4]
            //   8f4500               | pop                 dword ptr [ebp]
            //   9c                   | pushfd              
            //   60                   | pushal              

        $sequence_6 = { 60 ff35???????? 8f442438 9c }
            // n = 4, score = 400
            //   60                   | pushal              
            //   ff35????????         |                     
            //   8f442438             | pop                 dword ptr [esp + 0x38]
            //   9c                   | pushfd              

        $sequence_7 = { 9c ff742404 8d642434 e9???????? }
            // n = 4, score = 400
            //   9c                   | pushfd              
            //   ff742404             | push                dword ptr [esp + 4]
            //   8d642434             | lea                 esp, [esp + 0x34]
            //   e9????????           |                     

        $sequence_8 = { f5 83ef04 f5 ff37 }
            // n = 4, score = 400
            //   f5                   | cmc                 
            //   83ef04               | sub                 edi, 4
            //   f5                   | cmc                 
            //   ff37                 | push                dword ptr [edi]

        $sequence_9 = { 3b45f0 60 9c 8d642424 }
            // n = 4, score = 400
            //   3b45f0               | cmp                 eax, dword ptr [ebp - 0x10]
            //   60                   | pushal              
            //   9c                   | pushfd              
            //   8d642424             | lea                 esp, [esp + 0x24]

    condition:
        7 of them and filesize < 860160
}