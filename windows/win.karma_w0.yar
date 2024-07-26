import "pe"

rule win_karma_w0 {
    meta:
        author = "Blackberry Threat Research Team"
        description = "Detects Karma Ransomware 2021"
        date = "2021-10"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"
        source = "https://blogs.blackberry.com/en/2021/11/threat-thursday-karma-ransomware"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex"
        malpedia_rule_date = "20211108"
        malpedia_hash = ""
        malpedia_version = "20211108"
        malpedia_license = "Apache License 2.0"
        malpedia_sharing = "TLP:WHITE"
 
    strings:
        $s1 = "WW91ciBuZXR3b3JrIGhhcyBiZWVuIGJyZWFjaGVkIGJ5IEthcm1hIHJhbnNvbXdhcmUgZ3JvdXAu" ascii wide
        $x2 = "crypt32.dll" nocase
        $x3 = "KARMA" ascii wide
        $x4 = "Sleep" nocase                            

    condition:
        //PE File
        uint16(0) == 0x5a4d and
        //Base64 Karma Note
        all of ($s*) and
        //All Strings
        all of ($x*)
}
