rule win_njrat_w1 {
    meta:
        author = "Brian Wallace @botnet_hunter <bwall@ballastsecurity.net>"
        date = "2015-05-27"
        description = "Identify njRat"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Njrat.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a1 = "netsh firewall add allowedprogram " wide
        $a2 = "SEE_MASK_NOZONECHECKS" wide

        $b1 = "[TAP]" wide
        $b2 = " & exit" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}
