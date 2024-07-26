rule elf_persirai_w0 {
    meta:
        description = "Detects Persirai Botnet Malware"
        soure = "http://blog.trendmicro.com/trendlabs-security-intelligence/persirai-new-internet-things-iot-botnet-targets-ip-cameras/"
        author = "Tim Yeh"
        reference = "Internal Research"
        date = "2017-04-21"
        hash = "f736948bb4575c10a3175f0078a2b5d36cce1aa4cd635307d03c826e305a7489"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.persirai"
        malpedia_version = "20170509"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $x1 = "ftpupload.sh" fullword ascii
        $x2 = "/dev/misc/watchdog" fullword ascii
        $x3 = "/dev/watchdog" ascii
        $x4 = ":52869/picsdesc.xml" fullword ascii
        $x5 = "npxXoudifFeEgGaACScs" fullword ascii

        $s1 = "ftptest.cgi" fullword ascii
        $s2 = "set_ftp.cgi" fullword ascii
        $s3 = "2580e538f3723927f1ea2fdb8d57b99e9cc37ced1" fullword ascii
        $s4 = "023ea8c671c0abf77241886465200cf81b1a2bf5e" fullword ascii

    condition:
        uint16(0) == 0x457f and filesize < 300KB and ((1 of ($x*) and 1 of ($s*)) or 2 of ($s*))
}
