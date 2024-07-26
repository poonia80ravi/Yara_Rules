rule win_agent_btz_w0 {
    meta:
        author = "Symantec"
        source = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
        contribution = "pnx - removed FPs"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_btz"
        malpedia_version = "20171113"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $b = {C645????}
        $c = {C685??FEFFFF??}
        $d = {FFA0??0?0000}
        $e = {89A8??00000068??00000056FFD78B}
        $f = {00004889????030000488B}
        $tmp_fn = "FA.tmp"
    condition:
        ((#c > 200 and #b > 200 ) or (#d > 40) and (#e > 15 or #f > 30)) and $tmp_fn
}
