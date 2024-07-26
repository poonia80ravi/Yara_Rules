rule win_webmonitor_w0 {
    meta:
        description = "Revcode RAT"
        author = "James_inthe_box"
        reference = "ee1b9659f2193896ce3469b5f90b82af3caffcba428e8524be5a9fdf391d8dd8"
        date = "2020/02"
        maltype = "RAT"
        source = "https://pastebin.com/M2k5Vg3c"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webmonitor"
        malpedia_version = "20200304"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""

    strings:
        $string1 = "SCREEN_STREAM_START"
        $string2 = "CLIPBOARD_SET"
        $string3 = "SERVICES_RESUME"
        $string4 = "KEYLOG:"
        $string5 = "WEBCAM_DRIVERS"
        $string6 = "image.bmp" wide
        $string7 = "APPACTIVATE" wide
 
    condition:
        all of ($string*)
}
