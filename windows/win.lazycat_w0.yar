import "pe"

rule win_lazycat_w0 {

    meta:
        description = "Yara Rule for LazyCat"
        author = "Cybaze Zlab_Yoroi"
        last_updated = "2019_02_22"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lazycat"
        malpedia_version = "20190403"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $a = "LazyCat"
        $b = {48 74 74 70 53 65 72 76 65 72 4C 6F}
	$c = {0A 58 73 9E 00 00 0A 2A 0F 00 28 B0}
	$d = {80 A1 4E CD 13 56 80 9F}

    condition:
        pe.number_of_sections == 3 and pe.machine == pe.MACHINE_I386 and (($b and $c and $d) or ($a))
}
