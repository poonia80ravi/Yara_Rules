rule win_blister_w0 {
    meta:
        author = "Elastic Security"
        description = "Detects Blister loader."
        creation_date = "2021-12-20"
        last_modified = "2021-12-20"
        os = "Windows"
        category_type = "Trojan"
        family = "Blister"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
        source = "https://www.elastic.co/de/blog/elastic-security-uncovers-blister-malware-campaign"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blister"
        malpedia_rule_date = "20211223"
        malpedia_hash = ""
        malpedia_version = "20211223"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $a1 = {8D 45 DC 89 5D EC 50 6A 04 8D 45 F0 50 8D 45 EC 50 6A FF FF D7}
        $a2 = {75 F7 39 4D FC 0F 85 F3 00 00 00 64 A1 30 00 00 00 53 57 89 75}           
condition:
        any of them
}

