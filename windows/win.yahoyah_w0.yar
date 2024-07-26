/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule win_yahoyah_w0 {  
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
        $1 = "I am Admin"  
        $2 = "I am User"  
        $3 = "Run install success!"  
        $4 = "Service install success!"  
        $5 = "Something Error!"  
        $6 = "Not Configed, Exiting"  

    condition:  
        all of them  
}
