rule win_winnti_w2 {
    meta:
        author = "Bundesamt fuer Verfassungsschutz"
        source = "https://www.verfassungsschutz.de/download/anlage-2019-12-bfv-cyber-brief-2019-01.txt"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winnti"
        malpedia_version = "20191207"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $e1 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii nocase
        $e2 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii nocase
        $e3 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii nocase
        $e4 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
        $e5 = "BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}" nocase
    condition:
        (any of ($e*))
}
