rule win_xfilesstealer_w0 {

    meta:
        author      = "Johannes Bader @viql"
        date        = "2022-04-15"
        version     = "v1.0"
        description = "detects XFiles-Stealer"
        hash        = "d06072f959d895f2fc9a57f44bf6357596c5c3410e90dabe06b171161f37d690"
        tlp         = "TLP:WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfilesstealer"
        malpedia_rule_date = "20220425"
        malpedia_hash = ""
        malpedia_version = "20220425"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $ad_1 = "Telegram bot - @XFILESShop_Bot" wide
        $ad_2 = "Telegram support - @XFILES_Seller" wide

        $names_1 = "XFiles.Models.Yeti"
        $names_2 = "anti_vzlom_popki" // анти взлом попки
        $names_3 = "assType"
        $names_4 = "hackrjaw"

        $upload_1  = "zipx" wide
        $upload_2  = "user_id" wide
        $upload_3  = "passworlds_x" wide
        $upload_4  = "ip_x" wide
        $upload_5  = "cc_x" wide
        $upload_6  = "cookies_x" wide
        $upload_7  = "zip_x" wide
        $upload_8  = "contry_x" wide
        $upload_9  = "tag_x" wide
        $upload_10 = "piece" wide
            
    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($ad_*) or 
            all of ($names_*) or 
            all of ($upload_*)
        )
}
