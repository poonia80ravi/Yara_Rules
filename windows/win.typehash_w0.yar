rule win_typehash_w0 {
    meta:
        author = "Jeff White (karttoon@gmail.com) @noottrak"
        date = "15APR2020"
        hash = "d81ba465fe59e7d600f7ab0e8161246a5badd8ae2c3084f76442fb49f6585e95"
        description = "Detects an observed Negastealer campaign payload"
        source = "https://github.com/karttoon/iocs/blob/899dac6045a73045baa8966a16b7402d625ee26b/Negasteal/troj_win_negasteal.yar"

        malpedia_rule_date = "20200817"
        malpedia_hash = ""
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.typehash"
        malpedia_version = "20201007"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
	    $s1 = "Mozilla/5.0 (Windows NT 5.2) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.122 Safari/534.30"
	    $s2 = "news.php"
	    $s3 = "http://%s/%s"
	    $s4 = "type=0"
	    $s5 = "time=%s"
    condition:
	    all of them
}
