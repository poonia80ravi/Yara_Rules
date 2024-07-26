/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2019-08-07
   Identifier: APT41
   Reference: https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html
   License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule win_crackshot_w0 {
    meta:
        description = "Detects APT41 malware CRACKSHOT"
        author = "Florian Roth"
        reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
        date = "2019-08-07"
        score = 85
        hash = "993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crackshot"
        malpedia_version = "20190812"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = ";procmon64.exe;netmon.exe;tcpview.exe;MiniSniffer.exe;smsniff.exe" ascii

        $s1 = "RunUrlBinInMem" fullword ascii
        $s2 = "DownRunUrlFile" fullword ascii
        $s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" fullword ascii
        $s4 = "%s|%s|%s|%s|%s|%s|%s|%dx%d|%04x|%08X|%s|%s" fullword ascii
    condition:
        ( 1 of ($x*) or 2 of them )
}
