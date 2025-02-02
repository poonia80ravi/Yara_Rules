rule win_blackshades_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-10-07"
        version = "1"
        description = "Detects win.blackshades."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackshades"
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
        $sequence_0 = { fb ef 20ff 60 }
            // n = 4, score = 100
            //   fb                   | sti                 
            //   ef                   | out                 dx, eax
            //   20ff                 | and                 bh, bh
            //   60                   | pushal              

        $sequence_1 = { 0e 6c 50 fff5 2e0000 00c7 1cf0 }
            // n = 7, score = 100
            //   0e                   | push                cs
            //   6c                   | insb                byte ptr es:[edi], dx
            //   50                   | push                eax
            //   fff5                 | push                ebp
            //   2e0000               | add                 byte ptr cs:[eax], al
            //   00c7                 | add                 bh, al
            //   1cf0                 | sbb                 al, 0xf0

        $sequence_2 = { 0014fe 0200 f4 fd 0200 d0fd 0200 }
            // n = 7, score = 100
            //   0014fe               | add                 byte ptr [esi + edi*8], dl
            //   0200                 | add                 al, byte ptr [eax]
            //   f4                   | hlt                 
            //   fd                   | std                 
            //   0200                 | add                 al, byte ptr [eax]
            //   d0fd                 | sar                 ch, 1
            //   0200                 | add                 al, byte ptr [eax]

        $sequence_3 = { 1b01 01fb 301ce2 2000 0b7f0c 00f4 }
            // n = 6, score = 100
            //   1b01                 | sbb                 eax, dword ptr [ecx]
            //   01fb                 | add                 ebx, edi
            //   301ce2               | xor                 byte ptr [edx], bl
            //   2000                 | and                 byte ptr [eax], al
            //   0b7f0c               | or                  edi, dword ptr [edi + 0xc]
            //   00f4                 | add                 ah, dh

        $sequence_4 = { 60 3178ff 3606 0050ff 40 ff20 ff1e }
            // n = 7, score = 100
            //   60                   | pushal              
            //   3178ff               | xor                 dword ptr [eax - 1], edi
            //   3606                 | push                es
            //   0050ff               | add                 byte ptr [eax - 1], dl
            //   40                   | inc                 eax
            //   ff20                 | jmp                 dword ptr [eax]
            //   ff1e                 | lcall               [esi]

        $sequence_5 = { 1b01 01fb 301ce2 2000 }
            // n = 4, score = 100
            //   1b01                 | sbb                 eax, dword ptr [ecx]
            //   01fb                 | add                 ebx, edi
            //   301ce2               | xor                 byte ptr [edx], bl
            //   2000                 | and                 byte ptr [eax], al

        $sequence_6 = { 0e 6c 50 fff5 40 0000 00c7 }
            // n = 7, score = 100
            //   0e                   | push                cs
            //   6c                   | insb                byte ptr es:[edi], dx
            //   50                   | push                eax
            //   fff5                 | push                ebp
            //   40                   | inc                 eax
            //   0000                 | add                 byte ptr [eax], al
            //   00c7                 | add                 bh, al

        $sequence_7 = { 0458 ff405e 8b01 0400 7104 }
            // n = 5, score = 100
            //   0458                 | add                 al, 0x58
            //   ff405e               | inc                 dword ptr [eax + 0x5e]
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   0400                 | add                 al, 0
            //   7104                 | jno                 6

        $sequence_8 = { 0200 0000 6c 70ff 9e }
            // n = 5, score = 100
            //   0200                 | add                 al, byte ptr [eax]
            //   0000                 | add                 byte ptr [eax], al
            //   6c                   | insb                byte ptr es:[edi], dx
            //   70ff                 | jo                  1
            //   9e                   | sahf                

        $sequence_9 = { 0200 d0fd 0200 b0fd 0200 7cfd }
            // n = 6, score = 100
            //   0200                 | add                 al, byte ptr [eax]
            //   d0fd                 | sar                 ch, 1
            //   0200                 | add                 al, byte ptr [eax]
            //   b0fd                 | mov                 al, 0xfd
            //   0200                 | add                 al, byte ptr [eax]
            //   7cfd                 | jl                  0xffffffff

    condition:
        7 of them and filesize < 999424
}