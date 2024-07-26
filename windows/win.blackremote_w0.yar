rule win_blackremote_w0 {
    meta:
        author = "jeFF0Falltrades"
        ref = "https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/"
        source = "https://github.com/jeFF0Falltrades/IoCs/blob/master/Broadbased/blackremote_blackrat.md"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackremote"
        malpedia_version = "20200323"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""

    strings:
        $str_vers_1 = "16.0.0.0" wide ascii
        $str_vers_2 = "16.2.0.0" wide ascii
        $re_c2_1 = /%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?/ wide ascii
        $re_c2_2 = /\|!\*!\|\|!\*!\|/ wide ascii
        $hex_rsrc = { 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A }

    condition:
        2 of them and (1 of ($re*) or $hex_rsrc)
}
