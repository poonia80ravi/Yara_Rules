rule win_luminosity_rat_w0 {

    meta:
        author = "anonymous"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.luminosity_rat"
        malpedia_rule_date = "20200904"
        malpedia_version = "20200904"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "Luminosity is a Remote Administration Tool."
        $s2 = ":abuse@luminosity.link"
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x4550 and
        any of them
}
