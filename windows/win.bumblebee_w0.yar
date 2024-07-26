rule win_bumblebee_w0 {
    meta:
        author = "@AndreGironda"
        description = "BumbleBee / win.bumblebee"
        reference_md5 = "e6a046d1baa7cd2100bdf48102b8a144"
	    date = "March 29, 2022"
	    tlp = "White"

    malpedia_rule_date = "20220330"
    malpedia_hash = ""
	malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee"
	malpedia_version = "20220330"
	malpedia_license = "CC BY-NC-SA 4.0"
	malpedia_sharing = "TLP:WHITE"
    strings:
	$hex_140001d53 = { 48 8b 05 06 44 00 00 41 81 ea 06 28 00 00 49 31 80 48 02 00 00 49 8b 80 c8 00 00 00 48 05 28 01 00 00 48 01 41 08 49 8b }
	$hex_18000927a = { 48 8d 4c 24 50 e8 cc cc ff ff 90 4c 8d 45 b0 48 8d 54 24 50 48 8d 8d 00 01 00 00 e8 26 d3 ff ff 90 48 8b 44 24 68 48 83 f8 10 72 4a 48 ff c0 48 }
    condition:
        any of them
}
