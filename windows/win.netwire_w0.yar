rule win_netwire_w0 {
	meta:
		description = "NetWiredRC"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2014-12-23"
		filetype = "memory"
		version = "1.1" 
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/netwiredRC.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netwire"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        
	strings:
		$mutex = "LmddnIkX"

		$str1 = "%s.Identifier"
		$str2 = "%d:%I64u:%s%s;"
		$str3 = "%s%.2d-%.2d-%.4d"
		$str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
		$str5 = "%.2d/%.2d/%d %.2d:%.2d:%.2d"
		
		$klg1 = "[Backspace]"
		$klg2 = "[Enter]"
		$klg3 = "[Tab]"
		$klg4 = "[Arrow Left]"
		$klg5 = "[Arrow Up]"
		$klg6 = "[Arrow Right]"
		$klg7 = "[Arrow Down]"
		$klg8 = "[Home]"
		$klg9 = "[Page Up]"
		$klg10 = "[Page Down]"
		$klg11 = "[End]"
		$klg12 = "[Break]"
		$klg13 = "[Delete]"
		$klg14 = "[Insert]"
		$klg15 = "[Print Screen]"
		$klg16 = "[Scroll Lock]"
		$klg17 = "[Caps Lock]"
		$klg18 = "[Alt]"
		$klg19 = "[Esc]"
		$klg20 = "[Ctrl+%c]"

	condition: 
		$mutex or (1 of ($str*) and 1 of ($klg*))
}
