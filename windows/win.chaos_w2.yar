import "pe"    

rule win_chaos_w2 {           
    meta:
        description = "Detects Chaos Ransomware Builder"
        author = "BlackBerry Threat Research"
        date = "2022-05-10"
        source = "https://blogs.blackberry.com/en/2022/05/yashma-ransomware-tracing-the-chaos-family-tree"
        license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chaos"
        malpedia_rule_date = "20221007"
        malpedia_hash = ""
        malpedia_version = "20221007"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $s0 = "1qw0ll8p9m8uezhqhyd" ascii wide
        $s1 = "Chaos Ransomware Builder" ascii wide
        $s2 = "payloadFutureName" ascii wide
        $s3 = "read_it.txt" ascii wide
        $s4 = "encryptedFileExtension" ascii wide

        $x0 = "1098576" ascii wide
        $x1 = "2197152" ascii wide

    condition:
        //PE File
        uint16(0) == 0x5a4d and
        //All strings
        ((all of ($s*)) and (1 of ($x*)))

}
