rule win_dtrack_w0 {
    meta:
        author = "jeFF0Falltrades"
        source = "https://github.com/jeFF0Falltrades/IoCs/blob/master/APT/dtrack_lazarus_group.md"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dtrack"
        malpedia_version = "20191121"
        malpedia_license = "CC NC-BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $str_log = "------------------------------ Log File Create...." wide ascii
        $str_ua = "CCS_Mozilla/5.0 (Windows NT 6.1" wide ascii
        $str_chrome = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History" wide ascii
        $pdb = "Users\\user\\Documents\\Visual Studio 2008\\Projects\\MyStub\\Release\\MyStub.pdb" wide ascii
        $str_tmp = "%s\\~%d.tmp" wide ascii
        $str_exc = "Execute_%s.log" wide ascii
        $reg_use = /net use \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$ \/delete/
        $reg_move = /move \/y %s \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$\\Windows\\Temp\\MpLogs\\/

    condition:
        2 of them or $pdb
}
