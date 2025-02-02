rule win_cloudeye_w0 {
    meta:
        author = "ditekshen"
        description = "Shellcode injector and downloader via RegAsm.exe payload"
        source = "https://github.com/kevoreilly/CAPEv2/blob/master/data/yara/CAPE/SCInject.yar"
        malpedia_version = "20200204"
        malpedia_sharing = "TLP:WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloudeye"
        malpedia_license = ""
    strings:
        $s1 = "wininet.dll" fullword ascii
        $s2 = "ShellExecuteW" fullword ascii
        $s3 = "SHCreateDirectoryExW" fullword ascii
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii
        $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii

        $o1 = "msvbvm60.dll" fullword wide
        $o2 = "\\syswow64\\" fullword wide
        $o3 = "\\system32\\" fullword wide
        $o4 = "\\Microsoft.NET\\Framework\\" fullword wide
        $o5 = "USERPROFILE=" wide nocase
        $o6 = "windir=" fullword wide
        $o7 = "APPDATA=" nocase wide
        $o8 = "RegAsm.exe" fullword wide

        $url1 = "https://drive.google.com/uc?export=download&id=" ascii
        $url2 = "https://onedrive.live.com/download?cid=" ascii
        $url3 = "http://myurl/myfile.bin" fullword ascii
        $url4 = "http" ascii // fallback
    condition:
        all of ($s*) and 2 of ($o*) and 1 of ($url*)
}

