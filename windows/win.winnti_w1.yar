
rule win_winnti_w1 {
    meta:
        author = "BR Data"
        source = "https://github.com/br-data/2019-winnti-analyse/"
        date = "2019-07-24"
        description = "rules used for retrohunting by BR Data."
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winnti"
        malpedia_version = "20190822"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $cooper = "Cooper"
        $pattern = { e9 ea eb ec ed ee ef f0}
    condition:
        uint16(0) == 0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}
