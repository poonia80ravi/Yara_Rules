rule win_keybase_w0 {
meta:
	description = "Identifies KeyBase aka Kibex."
	author = "@bartblaze"
	hash = "cafe2d12fb9252925fbd1acb9b7648d6"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keybase"
    malpedia_version = "20190208"
    malpedia_license = "CC BY-NC-SA 4.0"
    malpedia_sharing = "TLP:WHITE"

strings:	
	$s1 = " End:]" ascii wide
	$s2 = "Keystrokes typed:" ascii wide
	$s3 = "Machine Time:" ascii wide
	$s4 = "Text:" ascii wide
	$s5 = "Time:" ascii wide
	$s6 = "Window title:" ascii wide
	
	$x1 = "&application=" ascii wide
	$x2 = "&clipboardtext=" ascii wide
	$x3 = "&keystrokestyped=" ascii wide
	$x4 = "&link=" ascii wide
	$x5 = "&username=" ascii wide
	$x6 = "&windowtitle=" ascii wide
	$x7 = "=drowssap&" ascii wide
	$x8 = "=emitenihcam&" ascii wide

condition:
	5 of ($s*) or 6 of ($x*) or (3 of ($s*) and 3 of ($x*) )
}
