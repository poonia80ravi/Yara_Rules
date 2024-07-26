rule win_whiteblackcrypt_w1 {
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Matches file extensions seen in WhiteBlackCrypt"
        ref = "https://cip.gov.ua/ua/news/informaciya-shodo-imovirnoyi-provokaciyi"
        version = "0.1"
        source = "https://github.com/stairwell-inc/threat-research/blob/main/whispergate/WhiteBlackCrypt.yara"
        malpedia_rule_date = "20220318"
        malpedia_hash = ""
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.whiteblackcrypt"
		malpedia_version = "20220318"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
    strings:
        $ = {2E 56 4D 44 4B 00 2E 56 4D 58 00 2E 47 50 47 00 2E 41 45 53 00 
             2E 41 52 43 00 2E 50 41 51 00 2E 42 5A 32 00 2E 54 42 4B 00 2E 
             42 41 4B 00 2E 54 41 52 00 2E 54 47 5A 00}
        $ = {2E 50 50 41 4D 00 2E 50 4F 54 58 00 2E 50 4F 54 4D 00 2E 45 44
             42 00 2E 48 57 50 00 2E 36 30 32 00 2E 53 58 49 00 2E 53 54 49 
             00 2E 53 4C 44 58 00 2E 53 4C 44 4D 00}
        $ = {2E 49 42 44 00 2E 4D 59 49 00 2E 4D 59 44 00 2E 46 52 4D 00 2E
        	 4F 44 42 00 2E 44 42 46 00 2E 44 42 00 2E 4D 44 42 00 2E 41 43 
        	 43 44 42 00 2E 53 51 4C 00 2E 53 51 4C 49 54 45 44 42 00}
    condition:
        3 of them    
}
