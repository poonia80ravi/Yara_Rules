rule win_lsassdumper_w0 {
	meta:
		author = "Felipe Duarte, Security Joes"
		description = "Detects Go binary lsassDumper"
		hash = "8bb7ae5117eec1db2287ef7812629e88e7e3692d39cc37415dc166bb8d56be03"
        malpedia_rule_date = "20220310"
        malpedia_hash = ""
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lsassdumper"
		malpedia_version = "20220310"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
	strings:
		$str1 = "lsassDumper/main.go"
		$str2 = "main.setSeDebugPrivilege"
		$str3 = "main.uploadLargeFile"
		$str4 = "main.findProcessByName"
		$str5 = "main.RandomString"
		$str6 = "[+] Start uploading %s to transfer.sh"
		$str7 = "[+] Process memory dump successful"
	condition:
		uint16(0) == 0x5A4D
		and all of them
}
