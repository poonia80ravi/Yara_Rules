rule win_megumin_w0 {
    meta:
        description = "Detecting Megumin v2"
        author = "Fumik0_"
        date = "2019-05-02"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.megumin"
        malpedia_version = "20190503"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        
    strings:
        $s1 = "Megumin/2.0" wide ascii
        $s2 = "/cpu" wide ascii
        $s3 = "/task?hwid=" wide ascii
        $s4 = "/gate?hwid=" wide ascii
        $s5 = "/suicide" wide ascii

    condition:
        all of them
}
