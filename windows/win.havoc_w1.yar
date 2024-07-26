rule win_havoc_w1 {
	//Detects the hashing routine used in Havoc C2
    
	meta:
		author = "embee_research @ HuntressLabs"
		vendor = "Huntress Research" 
		date = "2022/10/11"
		source = "https://raw.githubusercontent.com/embee-research/Yara/main/HavocDemonDJB2.yara"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havoc"
        malpedia_rule_date = "20221012"
        malpedia_hash = ""
        malpedia_version = "20221012"
        malpedia_sharing = "TLP:WHITE"
	strings:
		

		//  Hashing Routine of DLL   
		$dll = {b8 05 15 00 00 0f be 11 48 ff c1 84 d2 74 07 6b c0 21 01 d0 eb ef} 
		
		                             
        //Hashing Routine of Shellcode
		$shellcode = {41 80 f8 60 76 04 41 83 e8 20 6b c0 21 45 0f b6 c0 49 ff c1 44 01 c0 eb c4}
		
		
	condition:
		//PE or Shellcode or Shellcode
		//Leave as "any of them" for more robust (but compute expensive) searching
		(any of them) and (uint16(0) == 0x5a4d or uint16(0) == 0x00e8 or uint16(0) == 0x4856)
}

