rule win_alice_atm_w0 {
	meta:
		description = "Detects of ATM Malware ALICE"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1215265889844637696"
		date = "2020-01-09"
		hash = "6b2fac8331e4b3e108aa829b297347f686ade233b24d94d881dc4eff81b9eb30"
		source = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/ATM.Malware.ALICE.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alice_atm"
        malpedia_version = "20200113"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
		
	strings:
		$String1 = "Project Alice" ascii nocase
		$String2 = "Can't dispense requested amount." ascii nocase
		$String3 = "Selected cassette is unavailable" ascii nocase
		$String4 = "ATM update manager" wide nocase
		$String5 = "Input PIN-code for access" wide nocase
		$String6 = "Supervisor ID" wide nocase
		$Code1 = {50 68 08 07 00 00 6A 00 FF 75 0C FF 75 08 E8} // Get Cash Unit Info
		$Code2 = {50 6A 00 FF 75 10 FF 75 0C FF 75 08 E8} // Dispense Cash
		$Code3 = {68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 0B C0 75 29 6A} // Check Supervisor ID
		
	condition:
		uint16(0) == 0x5A4D and filesize < 200KB and 4 of ($String*) and all of ($Code*)
}
