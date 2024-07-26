rule win_caddywiper_w0 {
	meta:
		author = "IBM Security X-Force"
		description = "Detects CaddyWiper"
		threat_type = "Malware"
		rule_category = "Malware Family"
		usage = "Hunting and Identification"
		hash = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
		yara_version = "4.0.2"
		date_created = "15 March 22"
        malpedia_rule_date = "20220315"
        malpedia_hash = ""
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.caddywiper"
		malpedia_version = "20220316"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
	strings:
		$s1 = "DsRoleGetPrimaryDomainInformation" ascii fullword
		$hex1 = {
			C645??43 //'C'
			C645??3A //':'
			C645??5C //'\'
			C645??55 //'U'
			C645??73 //'s'
			C645??65 //'e'
			C645??72 //'r'
			C645??73 //'s'
		}
		$hex2 = {
			C645??44 // 'D'
			C645??65 // 'e'
			C645??76 // 'v'
			C645??69 // 'i'
			C645??63 // 'c'
			C645??65 // 'e'
			C645??49 // 'I'
			C645??6F // 'o'
			C645??43 // 'C'
			C645??6F // 'o'
			C645??6E // 'n'
			C645??74 // 't'
			C645??72 // 'r'
			C645??6F // 'o'
			C645??6C // 'l'
		}
	condition:
		uint16(0) == 0x5A4D and 
		all of them
}
