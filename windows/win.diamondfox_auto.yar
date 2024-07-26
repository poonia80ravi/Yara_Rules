rule win_diamondfox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2018-11-23"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diamondfox"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using yara-signator.
     * The code and documentation / approach will be published in the near future here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */

    strings:
        $sequence_0 = { ff258c104000 ff2588104000 ff2508114000 ff2570104000 }
            // n = 4, score = 2000
            //   ff258c104000         | jmp                 dword ptr [0x40108c]
            //   ff2588104000         | jmp                 dword ptr [0x401088]
            //   ff2508114000         | jmp                 dword ptr [0x401108]
            //   ff2570104000         | jmp                 dword ptr [0x401070]

        $sequence_1 = { ff253c104000 ff2550104000 ff2548104000 ff2584104000 }
            // n = 4, score = 2000
            //   ff253c104000         | jmp                 dword ptr [0x40103c]
            //   ff2550104000         | jmp                 dword ptr [0x401050]
            //   ff2548104000         | jmp                 dword ptr [0x401048]
            //   ff2584104000         | jmp                 dword ptr [0x401084]

        $sequence_2 = { ff25bc104000 ff25b4104000 ff25f0104000 ff2544104000 }
            // n = 4, score = 2000
            //   ff25bc104000         | jmp                 dword ptr [0x4010bc]
            //   ff25b4104000         | jmp                 dword ptr [0x4010b4]
            //   ff25f0104000         | jmp                 dword ptr [0x4010f0]
            //   ff2544104000         | jmp                 dword ptr [0x401044]

        $sequence_3 = { ff2568104000 ff253c104000 ff2550104000 ff2548104000 }
            // n = 4, score = 2000
            //   ff2568104000         | jmp                 dword ptr [0x401068]
            //   ff253c104000         | jmp                 dword ptr [0x40103c]
            //   ff2550104000         | jmp                 dword ptr [0x401050]
            //   ff2548104000         | jmp                 dword ptr [0x401048]

        $sequence_4 = { ff2500104000 ff2504104000 ff2508104000 ff2510114000 }
            // n = 4, score = 2000
            //   ff2500104000         | jmp                 dword ptr [0x401000]
            //   ff2504104000         | jmp                 dword ptr [0x401004]
            //   ff2508104000         | jmp                 dword ptr [0x401008]
            //   ff2510114000         | jmp                 dword ptr [0x401110]

        $sequence_5 = { ff2504104000 ff2508104000 ff2510114000 ff2560104000 }
            // n = 4, score = 2000
            //   ff2504104000         | jmp                 dword ptr [0x401004]
            //   ff2508104000         | jmp                 dword ptr [0x401008]
            //   ff2510114000         | jmp                 dword ptr [0x401110]
            //   ff2560104000         | jmp                 dword ptr [0x401060]

        $sequence_6 = { ff2544104000 ff25f8104000 ff2524114000 ff2530104000 }
            // n = 4, score = 2000
            //   ff2544104000         | jmp                 dword ptr [0x401044]
            //   ff25f8104000         | jmp                 dword ptr [0x4010f8]
            //   ff2524114000         | jmp                 dword ptr [0x401124]
            //   ff2530104000         | jmp                 dword ptr [0x401030]

        $sequence_7 = { ff2530104000 ff2594104000 ff25cc104000 ff2528104000 }
            // n = 4, score = 2000
            //   ff2530104000         | jmp                 dword ptr [0x401030]
            //   ff2594104000         | jmp                 dword ptr [0x401094]
            //   ff25cc104000         | jmp                 dword ptr [0x4010cc]
            //   ff2528104000         | jmp                 dword ptr [0x401028]

        $sequence_8 = { ff25e0104000 ff25ec104000 ff25c4104000 ff25d8104000 }
            // n = 4, score = 2000
            //   ff25e0104000         | jmp                 dword ptr [0x4010e0]
            //   ff25ec104000         | jmp                 dword ptr [0x4010ec]
            //   ff25c4104000         | jmp                 dword ptr [0x4010c4]
            //   ff25d8104000         | jmp                 dword ptr [0x4010d8]

        $sequence_9 = { ff2524104000 ff2514114000 ff2520114000 ff2518114000 }
            // n = 4, score = 2000
            //   ff2524104000         | jmp                 dword ptr [0x401024]
            //   ff2514114000         | jmp                 dword ptr [0x401114]
            //   ff2520114000         | jmp                 dword ptr [0x401120]
            //   ff2518114000         | jmp                 dword ptr [0x401118]

    condition:
        7 of them
}