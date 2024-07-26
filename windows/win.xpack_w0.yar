rule win_xpack_w0 {
    meta:
        author = "Symantec, a division of Broadcom"
        source = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/china-apt-antlion-taiwan-financial-attacks"
        hash = "390460900c318a9a5c9026208f9486af58b149d2ba98069007218973a6b0df66"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xpack"
        malpedia_rule_date = "20220207"
        malpedia_hash = ""
        malpedia_version = "20220207"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "C:\\Windows\\inf\\wdnvsc.inf" wide fullword
        $s2 = "PackService" wide fullword
        $s3 = "xPackSvc" wide fullword
        $s4 = "eG#!&5h8V$" wide fullword
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 
        and 3 of them
}
