rule win_infy_w0 {
    meta:
        author = "Florian Roth"
        description = "Detects Foudre Backdoor"
        info = "foudre dropper"
        reference = "https://goo.gl/Nbqbt6"
        date = "2017-08-01"
        hash = "7e73a727dc8f3c48e58468c3fd0a193a027d085f25fa274a6e187cf503f01f74"
        hash = "7ce2c5111e3560aa6036f98b48ceafe83aa1ac3d3b33392835316c859970f8bc"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.infy"
        malpedia_version = "20170803"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "initialization failed: Reinstall the program" fullword wide
        $s2 = "SnailDriver V1" fullword wide
        $s3 = "lp.ini" fullword wide
    condition:
        filesize < 100KB and 2 of them
}
