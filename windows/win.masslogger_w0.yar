rule win_masslogger_w0 {
    meta:        
        author = "govcert_ch"
        date = "20200604"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.masslogger"
        malpedia_rule_date = "20200608"
        malpedia_version = "20200608"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "MassLogger"
        $h1 = "A4E9167DC11A5B8BA7E09C85BAFDEA0B6E0B399CE50086545509017050B33097"
        $h2 = "AAA2C593325A6E943911DFD53B725C28A68B27938765C83DBE2EC87827F002D3"
        $h3 = "BF987C4258B4057871A8F1E5E2A46865B41E73B13409FE2876CA74DC1EB57B7A"
        $h4 = "EFEDAC4C9159D64FC0961D335BB5EC1CBC15F6545FA712EEEA543CD8711D2117"
    condition:
        any of them
}
