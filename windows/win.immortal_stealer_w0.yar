rule win_immortal_stealer_w0 {
   meta:
     author = "mak, MalwareLab.pl"
     hash = "8ba68bf60349bd375e81ded54072a0f60b152fc359ad9ac0e07fc736fd8ddfa2"
     description = "detects Immortal Stealer via its log messages"
     ref = "https://www.zscaler.com/blogs/research/immortal-information-stealer"

     malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.immortal_stealer"
     malpedia_version = "20200608"
     malpedia_license = "CC BY-NC-SA 4.0"
     malpedia_sharing = "TLP:WHITE"
  strings:
    $s0 = "Immortal Stealer" wide
    $s1 = "/stealer/files/upload.php?user={0}&hwid={1}" wide
    $s2 = "# Stealed Autofill by" wide
    $s3 = "# Stealed CC by" wide

  condition:
   2 of them
}

