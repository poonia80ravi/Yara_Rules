rule win_netc_w0 {
	meta:
		description = "Net Crawler used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netc"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s1 = "NetC.exe" wide
		$s2 = "Net Service"
	condition:
		all of them
}
