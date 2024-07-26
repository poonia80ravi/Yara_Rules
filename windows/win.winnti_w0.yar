
rule win_winnti_w0 {
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
        $load_magic = { C7 44 ?? ?? FF D8 FF E0 }
        $iter = { E9 EA EB EC ED EE EF F0 }
        $jpeg = { FF D8 FF E0 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5a4d and
        $jpeg and
        ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and
        for any i in (1..#jpeg): ( uint8(@jpeg[i] + 11) != 0 )
}
