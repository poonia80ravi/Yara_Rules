rule win_whiteblackcrypt_w0 {
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Matches strings seen in WhiteBlackCrypt"
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
        $ = ".encrpt3d"
        $ = "C:\\ProgramData\\CheckServiceD.exe"
        $ = "HOMEDRIVE"
        $ = "ye64T0p"
        $ = "USERPROFILE"
        $ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        5 of them    
}
