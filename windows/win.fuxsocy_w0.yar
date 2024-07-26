rule win_fuxsocy_w0 {
    meta:
        author = "Stephan Simon <stephan.simon@binarydefense.com>"
        date = "2019-10-24"
        description = "A ransomware tweeted about by @malwrhunterteam"
        modified = "2019-10-24"
        reference = "https://twitter.com/malwrhunterteam/status/1187360440734625798"
        tlp = "WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fuxsocy"
        malpedia_version = "20191031"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $n1 = "FuxSocy_Evaluated" wide
        $n2 = "FuxSocy_InstallPlace" wide
        $n3 = "FuxSocy_Instance" wide
 
        $s1 = "{RAND}" wide
        $s2 = "\\x*x.exe" wide
        $s3 = "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d" wide
        $s4 = "PT1M" wide
        $s5 = "PT0S" wide
        $s6 = "/d /c taskkill /f /pid %d > NUL & ping -n 1 127.0.0.1 > NUL & del \"%s\" > NUL & exit" wide
        $s7 = "/d /c start \"\" \"%s\"" wide
        $s8 = "Win32_ShadowCopy.ID='%s'" wide
        $s9 = "SuperHidden" wide
        $s10 = "ShowSuperHidden" wide
        $s11 = "Shell.IPC.%s" wide
        $s12 = "\\StringFileInfo\\%04x%04x\\%s" wide

    condition:
        filesize <= 100KB and
        (1 of ($n*) or 4 of ($s*))
}
