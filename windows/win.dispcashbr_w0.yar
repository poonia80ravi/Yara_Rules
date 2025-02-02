rule win_dispcashbr_w0 {
	meta:
		description = "Detects of ATM Malware DispCashBR"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1232944566208286720"
		date = "2020-02-27"
		hash = "7cea6510434f2c8f28c9dbada7973449bb1f844cfe589cdc103c9946c2673036"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dispcashbr"
        malpedia_version = "20200227"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
	strings:
		$String1 = "(*) Dispensando: %lu" ascii nocase
		$String2 = "COMANDO EXECUTADO COM SUCESSO" ascii nocase
		$String3 = "[+] FOI SACADO:  %lu R$ [+]" ascii nocase
		$DbgStr1 = "_Get_Information_cdm_cuinfo" ascii nocase
		$DbgStr2 = "_GET_INFORMATION_SHUTTER" ascii nocase
		$Code1 = {C7 44 24 08 00 00 00 00 C7 44 24 04 2F 01 00 00 89 04 24 E8} // CDM Info1
		$Code2 = {C7 44 24 08 00 00 00 00 C7 44 24 04 17 05 00 00 89 04 24 E8} // CDM Info2
		$Code3 = {89 4C 24 08 C7 44 24 04 2E 01 00 00 89 04 24 E8} // Dispense Cash
		
	condition:
		uint16(0) == 0x5A4D and filesize < 100KB and 2 of ($String*) and 1 of ($DbgStr*) and all of ($Code*)
}
