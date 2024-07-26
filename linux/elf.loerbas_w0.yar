rule elf_loerbas_w0 {
	meta:
		author = "Tillmann Werner"
		description = "detects loader module"
		source = "https://twitter.com/nunohaien/status/1261281419483140096"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.loerbas"
        malpedia_version = "20200518"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $fragemnt = { 61 31 C2 8B 45 FC 48 98 }
    condition:
        all of them
}
