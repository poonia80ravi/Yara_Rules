rule win_yahoyah_w1 {
    meta:
        author      = "Rapid7 Labs"
        date        = "2013/06/07"
        description = "Strings inside"
        reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/KeyBoy.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yahoyah"
        malpedia_version = "20170517"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
        
    strings:  
        $1 = "$login$"  
        $2 = "$sysinfo$"  
        $3 = "$shell$"  
        $4 = "$fileManager$"  
        $5 = "$fileDownload$"  
        $6 = "$fileUpload$"  

    condition:  
        all of them  
} 
