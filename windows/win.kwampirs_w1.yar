rule win_kwampirs_w1 {
    meta:
        author = "pancak3lullz"
        yara_version = "3.7.0"
        date = "14 Jan 20"
        description = "Kwampirs installer xor keys and Unicode string length routine"
        source = "https://twitter.com/pancak3lullz/status/1225536379834290177"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kwampirs"
        malpedia_version = "20200211"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""
    strings:
        $string_key = { 6C 35 E3 31 1B 23 F9 C9 65 EB F3 07 93 33 F2 A3 }
        $resource_key = { 28 99 B6 17 63 33 EE 22 97 97 55 B5 7A C4 E1 A4 }
        $strlenW = { 33 C0 85 C9 74 17 80 3C 41 00 75 07 80 7C 41 01 00 74 0A 3D 00 94 35 77 73 03 40 EB E9 C3 }
    condition:
        uint16(0) == 0x5a4d and 2 of them
}
