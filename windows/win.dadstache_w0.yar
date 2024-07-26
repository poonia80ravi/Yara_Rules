rule win_dadstache_w0 {
    meta:
        author =  "Elastic Security"
        description = "APT40 second stage implant"
        source = "https://www.elastic.co/blog/advanced-techniques-used-in-malaysian-focused-apt-campaign"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dadstache"
        malpedia_version = "20200626"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a = "/list_direction" fullword wide
        $b = "/post_document" fullword wide
        $c = "/postlogin" fullword wide
        $d = "Download Read Path Failed %s" fullword ascii
        $e = "Open Pipe Failed %s" fullword ascii
        $f = "Open Remote File %s Failed For: %s" fullword ascii
        $g = "Download Read Path Failed %s" fullword ascii
        $h = "\\cmd.exe" fullword wide
    condition:
        all of them
}
