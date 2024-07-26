rule win_xfsadm_w0 {
    meta:
        description = "Detects ATM Malware XFSADM"
        author = "Frank Boldewin (@r3c0nst)"
        reference = "https://twitter.com/r3c0nst/status/1149043362244308992"
        date = "2019-06-21"
        hash1 = "2740bd2b7aa0eaa8de2135dd710eb669d4c4c91d29eefbf54f1b81165ad2da4d"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfsadm"
        malpedia_version = "20190712"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $Code1 = {68 88 13 00 00 FF 35 ?? ?? ?? ?? 68 CF 00 00 00 50 FF 15} // Read Card Data
        $Code2 = {68 98 01 00 00 50 FF 15} // Get PIN Data
        $Mutex = "myXFSADM" nocase wide
        $MSXFSDIR = "C:\\Windows\\System32\\msxfs.dll" nocase ascii
        $XFSCommand1 = "WfsExecute" nocase ascii
        $XFSCommand2 = "WfsGetInfo" nocase ascii
        $PDB = "C:\\Work64\\ADM\\XFS\\Release\\XFS.pdb" nocase ascii
        $WindowName = "XFS ADM" nocase wide
        $FindWindow = "ADM rec" nocase wide
        $LogFile = "xfs.log" nocase ascii
        $TmpFile = "~pipe.tmp" nocase ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and 4 of them
}

