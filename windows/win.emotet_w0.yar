rule win_emotet_w0 {
    meta:
        author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
        source = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
        description = "The modified emotet binary replaces the original emotet on the system of the victim. The original emotet is copied to a quarantine for evidence-preservation."
        note = "The quarantine folder depends on the scope of the initial emotet infection (user or administrator). It is the temporary folder as returned by GetTempPathW under a filename starting with UDP as returned by GetTempFileNameW. To prevent accidental reinfection by a user, the quarantined emotet is encrypted using RC4 and a 0x20 bytes long key found at the start of the quarantined file (see $key)."
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
        $key at 0
}
