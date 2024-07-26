rule win_blacknet_rat_w0 { 
    meta: 
        author = "K7 Security Labs"
        date = "2020-12-16"
        version = "1"
        description = "BlackNet Payload"
        source = "https://labs.k7computing.com/index.php/anti-analysis-techniques/dark-side-of-blacknet-rat-part-2/"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blacknet_rat"
        malpedia_rule_date = "20201216"
        malpedia_hash = ""
        malpedia_version = "20201216"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings: 
        $fun1 = "MAINWINDOWTITLE" nocase 
        $fun2 = "getkeystate" nocase 
        $fun3 = "getkeyboardstate" nocase 
        $fun4 = "mapvirtualkey" nocase 
        $fun5 = "copyfromscreen" nocase 
        $fun6 = "uploadfile" nocase 
        $filename1 = "Windows_update.exe" nocase wide 
        $filename2 = "Adobe Photoshop CS.exe" nocase wide 
        $filename3 = "updatedpayload.exe" nocase wide 
    condition: 
            (uint16(0) == 0x5A4D
        and 
            (3 of ($fun*)
        and
            (1 of ($filename*))))
}
