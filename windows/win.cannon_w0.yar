rule win_cannon_w0 {
    meta:
        description = "Detects Sofacy Cannon Loader"
        author = "@VK_Intel"
        date = "2018-11-24"
        hash = "61a1f3b4fb4dbd2877c91e81db4b1af8395547eab199bf920e9dd11a1127221e"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cannon"
        malpedia_version = "20190106"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        
    strings:

    $pdb = "c:\\Users\\Garry\\Desktop\\cannon\\obj\\x86\\Debug\\wsslc.pdb" fullword ascii
    $exe = "wsslc.exe" fullword ascii wide

    $s0 = "cannon" fullword ascii wide
    $s1 = "cannon.Form1.resources" fullword ascii wide
    $s2 = "cannon.Properties.Resources.resources" fullword ascii wide

    $c0 = "Form1" fullword ascii wide
    $c1 = "Lenor" fullword ascii wide
    $c2 = "MDat" fullword ascii wide
    $c3 = "AUTH" fullword ascii wide
    $c4 = "Program" fullword ascii wide

    $f0 = "start_Tick" fullword ascii wide
    $f1 = "inf_Tick" fullword ascii wide
    $f2 = "screen_Tick" fullword ascii wide
    $f3 = "txt_Tick" fullword ascii wide
    $f4 = "load_Tick" fullword ascii wide
    $f5 = "subject_Tick" fullword ascii wide
    $f6 = "run_Tick" fullword ascii wide
    $f7 = "eTim_Tick" fullword ascii wide

    condition:
        ((2 of ($c*) and 4 of ($f*)) or (1 of ($s*) and ($pdb or $exe))) or (all of them)
}
