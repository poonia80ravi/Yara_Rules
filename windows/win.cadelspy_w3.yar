rule win_cadelspy_w3 {
    meta:
        author = "Symantec"
        source = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cadelspy"
        malpedia_version = "20170410"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $s1 = "AppInit_DLLs" wide ascii
        $s2 = { 5C 00 62 00 61 00 63 00 6B 00 75 00 70 00 00 }
        $s3 = { 5C 00 75 00 70 00 64 00 61 00 74 00 65 00 00 }
        $s4 = "\\cmd.exe" wide ascii
    condition:
        all of them
}
