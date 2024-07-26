rule win_ozh_rat_w0 {
    meta:
        description = "Detects OZH RAT"
        author = "@BushidoToken"
        reference = "https://blog.bushidotoken.net/2020/05/ozh-rat-new-net-malware.html"
        source = "https://raw.githubusercontent.com/WilliamThomas-sec/IOCs-YARAs/master/OZH_RAT.yar"
        date = "2020-06-05"
        hash = "15f39214b98241e7294b77d26e374e103b85ef1f189fb3ab162bda4b3423dd6c"
        hash = "b2ba16bcd7cb9a884f52420b1e025fc2af2610cf4324847366cc9c45e79c61c1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ozh_rat"
        malpedia_rule_date = "20200608"
        malpedia_version = "20200608"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a = "OzhSecSys.My" nocase
        $b = "OzhSecSys.My.Resources" nocase
	    $c = "OzhSecSys.pdb" nocase
    condition:
       any of them
}
