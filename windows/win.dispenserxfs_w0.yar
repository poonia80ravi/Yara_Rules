import "pe"

rule win_dispenserxfs_w0 {
    meta:
        description = "Detects ATM Malware DispenserXFS"
        author = "@Xylit0l @r3c0nst / Modified by Florian Roth"
        reference = "https://twitter.com/r3c0nst/status/1100775857306652673"
        date = "2019/02/27"
        score = 80
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dispenserxfs"
        malpedia_version = "20190307"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $xc1 = { 68 FF FF 00 00 68 60 EA 00 00 6A 10 }
        $s1 = "\\dispenserXFS.pdb" ascii wide
        $s3 = "C:\\xfsasdf.txt" fullword ascii
        $s4 = "Injected mxsfs killer into %d." fullword ascii
        $s5 = "Waiting for freeze msxfs processes..." fullword ascii

    condition:
        1 of them or pe.imphash() == "617e037ae26d1931818db0790fb44bfe"
}
