rule win_parallax_w0 {
    meta:
        author = "jeFF0Falltrades"
        source = "https://github.com/jeFF0Falltrades/IoCs/blob/master/Broadbased/parallax_rat.md"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parallax"
        malpedia_version = "20200327"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $str_ws = ".DeleteFile(Wscript.ScriptFullName)" wide ascii
        $str_cb_1 = "Clipboard Start" wide ascii
        $str_cb_2 = "Clipboard End" wide ascii
        $str_un = "UN.vbs" wide ascii
        $hex_keylogger = { 64 24 ?? C0 CA FA }

    condition:
        3 of them
}
