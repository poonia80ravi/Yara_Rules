rule win_sockbot_w0 {
	meta:
		author = "Felipe Duarte, Security Joes"
		description = "Detects Go binary Sockbot"
		hash = "7dc13eae4e15869024ec1fd2650e4f8444d53dfa2dd7d302f845cd94289fe5f2"
        malpedia_rule_date = "20220310"
        malpedia_hash = ""
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sockbot"
		malpedia_version = "20220310"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
	strings:
		$str1 = "main.handleRelay"
		$str2 = "main.verifyTlsCertificate"
		$str3 = "main.FindProcess"
		$str4 = "main.hideConsole"
		$str5 = "main.startSocksProxy"
		$str6 = "main.CreateSchedTask"
		$str7 = "main.relay"
		$str8 = "Connecting to relay server..."
		$str9 = "Could not start SOCKS5 proxy !"
	condition:
		uint16(0) == 0x5A4D 
		and all of them
}
