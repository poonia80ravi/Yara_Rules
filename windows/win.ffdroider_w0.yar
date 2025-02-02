rule win_ffdroider_w0 {
    meta:
        author      = "Johannes Bader @viql"
        date        = "2022-04-08"
        description = "detects FFDroider"
        tlp         = "white"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ffdroider"
        malpedia_rule_date = "20220414"
        malpedia_hash = ""
        malpedia_version = "20220414"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $string_pdb  = "F:\\FbRobot\\Release\\FbRobot.pdb"
        $string_mutex = "37238328-1324242-5456786-8fdff0-67547552436675" wide
        $string_path  = "/seemorebty/"

        $tld_ca = ".ca" wide
        $tld_cn = ".cn" wide
        $tld_eg = ".eg" wide
        $tld_fr = ".fr" wide
        $tld_de = ".de" wide
        $tld_in = ".in" wide
        $tld_it = ".it" wide
        $tld_cojp = ".co.jp" wide
        $tld_nl = ".nl" wide
        $tld_pl = ".pl" wide
        $tld_sa = ".sa" wide
        $tld_sg = ".sg" wide
        $tld_es = ".es" wide
        $tld_ae = ".ae" wide
        $tld_couk = ".co.uk" wide
        $tld_com = ".com" wide
        $tld_comau = ".com.au" wide
        $tld_combr = ".com.br" wide
        $tld_commx = ".com.mx" wide
        $tld_comtr = ".com.tr" wide
        
        $facebook_1 = "https://www.facebook.com/ads/manager/account_settings/account_billing" wide
        $facebook_2 = "https://www.facebook.com/pages/?category=your_pages&ref=bookmarks"
        $facebook_3 = "https://www.facebook.com/bookmarks/pages?ref_type=logout_gear" 
        
    condition:
        2 of ($string_*) or
        (
            all of ($tld_*) and
            all of ($facebook_*)
        ) 
}
