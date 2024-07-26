import "pe"

rule win_powerkatz_w0 {

    meta:
        description = "Yara Rule for LazyCat"
        author = "Cybaze Zlab_Yoroi"
        last_updated = "2019_02_22"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powerkatz"
        malpedia_version = "20190403"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $a1 = {C7 E8 3F}
        $b1 = {7C 43 3D}
        $a2 = {A4 58 24 8A 3A 36 8D 4B 89 15 15 33 CE 1D 1D F2}
        $b2 = {A9 B5 2D 2A 00 47 AC 44 97 7A F5 D0 04 09 75 13}

    condition:
        pe.number_of_sections == 3 and pe.machine == pe.MACHINE_I386 and (($a1 or $b1) and ($a2 or $b2))
}
