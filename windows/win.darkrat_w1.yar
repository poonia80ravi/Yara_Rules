rule win_darkrat_w1 {
    meta:
        description = "Darkrat"
        author = "James_inthe_box"
        reference = "https://github.com/albertzsigovits/malware-writeups/tree/master/DarkRATv2"
        date = "2019/08"
        maltype = "RAT"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkrat"
        malpedia_version = "20191012"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
 
    strings:
        $string1 = "Set objShell = WScript.CreateObject(\"WScript.Shell\")"
        $string2 = "&taskstatus="
        $string3 = "network reset"
        $string4 = "text/plain"
        $string5 = "&antivirus="
        $string6 = "request="
        $string7 = "&arch="
 
    condition:
        all of ($string*)
}
