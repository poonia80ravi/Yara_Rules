rule win_xpack_w1 {
  meta:
    author = "Symantec, a division of Broadcom"
    source = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/china-apt-antlion-taiwan-financial-attacks"
    hash = "12425edb2c50eac79f06bf228cb2dd77bb1e847c4c4a2049c91e0c5b345df5f2"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xpack"
    malpedia_rule_date = "20220207"
    malpedia_hash = ""
    malpedia_version = "20220207"
    malpedia_license = "CC BY-NC-SA 4.0"
    malpedia_sharing = "TLP:WHITE"
  strings:
     $s1 = "Length or Hash destoryed" wide fullword
     $s2 = "tag unmatched" wide fullword
     $s3 = "File size mismatch" wide fullword
     $s4 = "DESFile" wide fullword
     $p1 = "fomsal.Properties.Resources.resources" wide fullword
     $p2 = "xPack.Properties.Resources.resources" wide fullword
     $p3 = "foslta.Properties.Resources.resources" wide fullword
  condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 
    and (2 of ($s*) or any of ($p*))
}
