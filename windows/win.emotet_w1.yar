rule win_emotet_w1 {
    meta:
        author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
        source = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
        description = "This rule targets a modified emotet binary deployed by the Bundeskriminalamt on the 26th of January 2021."
        note = "The binary will replace the original emotet by copying it to a quarantine. It also contains a routine to perform a self-deinstallation on the 25th of April 2021. The three-month timeframe between rollout and self- deinstallation was chosen primarily for evidence purposes as well as to allow remediation."
        sharing = "TLP:WHITE"
        version = "20210323"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
        malpedia_rule_date = "20210421"
        malpedia_hash = ""
        malpedia_version = "20210421"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }
    condition:
        filesize >  300KB and
        filesize < 700KB and
        uint16(0) == 0x5A4D and
        $key
}


