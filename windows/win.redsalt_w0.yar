rule win_redsalt_w0 {
	meta:
		author = "Microsoft"
		description = "Dipsind variant"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redsalt"
		malpedia_version = "20200103"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
	strings:
		$str1 = "VPLRXZHTU"
		$str2 = {64 6F 67 32 6A 7E 6C}
		$str3 = "Dqpqftk(Wou\"Isztk)"
		$str4 = "StartThreadAtWinLogon"
   condition:
		all of them
}
