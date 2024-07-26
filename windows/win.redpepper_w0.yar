import "pe"

rule win_redpepper_w0 {
   meta:
      author = "Microsoft, modified by @r0ny_123"
      description = "Adupib SSL Backdoor"
      hash = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
      hash = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
      malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redpepper"
      malpedia_version = "20200101"
      malpedia_license = "CC BY-NC-SA 4.0"
      malpedia_sharing = "TLP:WHITE"
   strings:
      $str1 = "POLL_RATE"
      $str2 = "OP_TIME(end hour)"
      $str3 = "%d:TCP:*:Enabled"
      $s1 = "%s[PwFF_cfg%d]"
      $str4 = "Fake_GetDlgItemTextW: ***value***="

   condition:
      pe.exports("DllGetClassObject")
      and pe.exports("GetStartObjectEx") and (all of them or $s1)
}
