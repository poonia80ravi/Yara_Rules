rule win_pngdowner_w0 {
    meta: 
        author = "CrowdStrike, Inc."
        description = "PUTTER PANDA - PNGDOWNER"
        date = "2014-03-30" version = "1.0"
        in_the_wild = true
        copyright = "CrowdStrike, Inc."
        actor = "Putter Panda"
        actor_type = "APT"
        source = "https://www.iocbucket.com/iocs/7f7999ab7f223409ea9ea10cff82b064ce2a1a31"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pngdowner"
        malpedia_version = "20180911"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings: 
        $myagent = "myAgent" 
        $readfile = "read file error:" 
        $downfile = "down file success" 
        $avail = "Avaliable data:%u bytes" 
    condition: 
        3 of them
}
