rule win_robinhood_w0 { 
    meta:
        author = "anonymous submission"
        description = "Unpacked RobinHood ransomware"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.robinhood"
        malpedia_version = "20190510"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $go1 = "go.buildid" 
        $go2 = "Go build ID:" 
        $rh1 = "c:\\windows\\temp\\pub.key" nocase 
        $rh2 = ".enc_robbinhood" nocase 
        $rh3 = "cmd.exe /c net use * /DELETE /Y" nocase 
        $rh4 = "CoolMaker" nocase 
        $rh5= "ShadowFucks" nocase 
        $rh6= "RecoveryFCK" nocase 
        $rh7= "ServiceFuck" nocase 
    condition: 
        all of ($go*) and any of ($rh*)
}
