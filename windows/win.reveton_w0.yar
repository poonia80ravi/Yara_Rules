rule win_reveton_w0 {
    meta:
        author = "A malpedia community member"
        version = "1"
        description = "targets reveton"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.reveton"
        malpedia_rule_date = "2020213"
        malpedia_hash = ""
        malpedia_version = "2020213"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
  strings:
      $str1 = "Internet Explorer\\Main\\NoProtectedModeBanner"
      $str2 = "Internet Settings\\Zones\\4\\1609"
      $str3 = "START \"ok\" rundll32.exe"
      $str4 = "Source\\SysUtils.pas"
      $str5 = "%systemroot%\\regedit.exe"
      $path = "JimmMonsterNew\\ServerWinlock\\Source\\SysUtils.pas"
  condition:
      (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
      (all of ($str*) or $path)
}
