rule win_poison_ivy_w0 {
    meta:
        author = "Matthew Ulm"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/pivy.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poison_ivy"
        malpedia_version = "20170517"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        // presence of pivy in memory
        $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} 

    condition: 
        any of them
}
