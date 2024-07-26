rule elf_loerbas_w1 {
	meta:
		author = "Tillmann Werner"
		description = "detects cleaner module"
		source = "https://twitter.com/nunohaien/status/1261281419483140096"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.loerbas"
        malpedia_version = "20200518"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $fragemnt = { 14 CC FC 28 25 DE B9 }
    condition:
        all of them
}
