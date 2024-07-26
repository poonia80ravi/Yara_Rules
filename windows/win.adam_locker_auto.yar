rule win_adam_locker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-05-30"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.4.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adam_locker"
        malpedia_rule_date = "20200529"
        malpedia_hash = "92c362319514e5a6da26204961446caa3a8b32a8"
        malpedia_version = "20200529"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using yara-signator.
     * The code and documentation / approach is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { d7 baf7bf75ee bdefdd7baf 7bf7 5e ebde }
            // n = 6, score = 100
            //   d7                   | xlatb               
            //   baf7bf75ee           | mov                 edx, 0xee75bff7
            //   bdefdd7baf           | mov                 ebp, 0xaf7bddef
            //   7bf7                 | jnp                 0xfffffff9
            //   5e                   | pop                 esi
            //   ebde                 | jmp                 0xffffffe0

        $sequence_1 = { d7 baf7bf75ee bdefdd7baf 7bf7 5e ebde fd }
            // n = 7, score = 100
            //   d7                   | xlatb               
            //   baf7bf75ee           | mov                 edx, 0xee75bff7
            //   bdefdd7baf           | mov                 ebp, 0xaf7bddef
            //   7bf7                 | jnp                 0xfffffff9
            //   5e                   | pop                 esi
            //   ebde                 | jmp                 0xffffffe0
            //   fd                   | std                 

        $sequence_2 = { bdefdd7baf 7bf7 5e ebde }
            // n = 4, score = 100
            //   bdefdd7baf           | mov                 ebp, 0xaf7bddef
            //   7bf7                 | jnp                 0xfffffff9
            //   5e                   | pop                 esi
            //   ebde                 | jmp                 0xffffffe0

        $sequence_3 = { defd d7 baf7bf75ee bdefdd7baf }
            // n = 4, score = 100
            //   defd                 | fdivp               st(5)
            //   d7                   | xlatb               
            //   baf7bf75ee           | mov                 edx, 0xee75bff7
            //   bdefdd7baf           | mov                 ebp, 0xaf7bddef

        $sequence_4 = { defd d7 baf7bf75ee bdefdd7baf 7bf7 }
            // n = 5, score = 100
            //   defd                 | fdivp               st(5)
            //   d7                   | xlatb               
            //   baf7bf75ee           | mov                 edx, 0xee75bff7
            //   bdefdd7baf           | mov                 ebp, 0xaf7bddef
            //   7bf7                 | jnp                 0xfffffff9

        $sequence_5 = { defd d7 baffd7f9ff 00fb f75eeb defd }
            // n = 6, score = 100
            //   defd                 | fdivp               st(5)
            //   d7                   | xlatb               
            //   baffd7f9ff           | mov                 edx, 0xfff9d7ff
            //   00fb                 | add                 bl, bh
            //   f75eeb               | neg                 dword ptr [esi - 0x15]
            //   defd                 | fdivp               st(5)

        $sequence_6 = { ee bdefdd7baf 7bf7 5e ebde }
            // n = 5, score = 100
            //   ee                   | out                 dx, al
            //   bdefdd7baf           | mov                 ebp, 0xaf7bddef
            //   7bf7                 | jnp                 0xfffffff9
            //   5e                   | pop                 esi
            //   ebde                 | jmp                 0xffffffe0

        $sequence_7 = { f75eeb defd d7 baffd7f9ff 00fb }
            // n = 5, score = 100
            //   f75eeb               | neg                 dword ptr [esi - 0x15]
            //   defd                 | fdivp               st(5)
            //   d7                   | xlatb               
            //   baffd7f9ff           | mov                 edx, 0xfff9d7ff
            //   00fb                 | add                 bl, bh

        $sequence_8 = { f75eeb defd d7 baffd7f9ff 00fb f75eeb defd }
            // n = 7, score = 100
            //   f75eeb               | neg                 dword ptr [esi - 0x15]
            //   defd                 | fdivp               st(5)
            //   d7                   | xlatb               
            //   baffd7f9ff           | mov                 edx, 0xfff9d7ff
            //   00fb                 | add                 bl, bh
            //   f75eeb               | neg                 dword ptr [esi - 0x15]
            //   defd                 | fdivp               st(5)

        $sequence_9 = { baffd7f9ff 00fb f75eeb defd }
            // n = 4, score = 100
            //   baffd7f9ff           | mov                 edx, 0xfff9d7ff
            //   00fb                 | add                 bl, bh
            //   f75eeb               | neg                 dword ptr [esi - 0x15]
            //   defd                 | fdivp               st(5)

    condition:
        7 of them and filesize < 991232
}