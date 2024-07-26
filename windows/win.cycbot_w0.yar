rule win_cycbot_w0 {

    meta:
        author = "anonymous"
        date = "2020-11-06"
        description = "Captures characteristic strings of CycBot."
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cycbot"
        malpedia_rule_date = "20201106"
        malpedia_hash = ""
        malpedia_version = "20201106"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

  strings:
      $net_1 = "t=t&hrs=%d&q=id=1000&ver=%s&s=%d"
      $net_2 = "&system=%d&id=%s&hwid=%s&search=%s"
      $net_3 = "http://%s/s.php?c=121&id=%s"
      $net_4 = "pmv=2&id=%s&hwid=%s"
      $net_5 = "t=%s&p4=0&q=%s&z22=0&s=%d&hrs=%d"
      $s_1 = "SELECT_RESERV_SRV_%d"
      $s_2 = "_PRM_NAME_TASK_LOADER_5"
      $s_3 = "LST_TM_OF_PNG"
      $mutex_1 = "4A3282FEF482C0F79E1"
      $mutex_2 = "{0ECE180F-6E9E-4FA6-A154-6876D9DB8906}"
      $mutex_3 = "{C66E79CE-8935-4ed9-A6B1-4983619CB925}"
      $mutex_4 = "{35BCA615-C82A-4152-8857-BCC626AE4C8D}"

  condition:
      (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and 5 of them
}
