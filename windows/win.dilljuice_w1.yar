rule win_dilljuice_w1 {
    meta:
        author = "FireEye"
        source = "https://www.youtube.com/watch?v=a_CYCoL81bw"
        date = "2019-07-08"
        description = "Detection of DILLJUICE.B through its dropper"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dilljuice"
        malpedia_version = "20190708"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
	    $b = { ff 2f fa ff }
	condition:
	    uint16(0) == 0x5a4d and $b and for any i in (#b): 
	    (((uint32(@b[i]+0x4)+uint32(@b[i]+0x8))%0xff)^uint8(@b[i]+0xc) 
		    == 0x4d and 
	    ((uint32(@b[i]+0x4)+2*uint32(@b[i]+0x8))%0xff)^uint8(@b[i]+0xd) 
		    == 0x5a)
}
