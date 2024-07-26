rule win_artfulpie_w0 {
   meta:
      description = "Detects APT38 ARTFULPIE"
      author = "Emanuele De Lucia"
	  tlp = "white"
	  malfamily = "ARTFULPIE"
      actor = "Lazarus Group"
      actor_type = "APT"
	  malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.artfulpie"
	  malpedia_version = "20200227"
	  malpedia_license = "CC BY-NC-SA 4.0"
	  malpedia_sharing = "TLP:WHITE"
   strings:
      $a = "PPPh @A" fullword ascii
      $b = "3>3D3M3X3h3" fullword ascii
	  $c = "2`2d2h2p8t8x8|8" fullword ascii
	  $d = {C7 43 (1C|20) (60|70) 1E 40 00}
   condition:
      filesize < 200KB and 
	  uint16(0) == 0x5a4d and 
	  all of them
}
