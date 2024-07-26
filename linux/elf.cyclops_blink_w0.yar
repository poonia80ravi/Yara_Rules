rule elf_cyclops_blink_w0 {
   meta:
      author = "NCSC"
      description = "Detects notable strings identified within the Cyclops Blink executable"
      hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
      hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
      reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
      date = "2022-02-23"
      malpedia_rule_date = "20220316"
      malpedia_hash = ""
      malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.cyclops_blink"
      malpedia_version = "20220316"
      malpedia_license = "CC BY-NC-SA 4.0"
      malpedia_sharing = "TLP:WHITE"
   strings:
      // Process names masqueraded by implant
      $proc_name1 = "[kworker/0:1]"
      $proc_name2 = "[kworker/1:1]"
      // DNS query over SSL, used to resolve C2 server address
      $dns_query = "POST /dns-query HTTP/1.1\x0d\x0aHost: dns.google\x0d\x0a"
      // iptables commands
      $iptables1 = "iptables -I %s -p tcp --dport %d -j ACCEPT &>/dev/null"
      $iptables2 = "iptables -D %s -p tcp --dport %d -j ACCEPT &>/dev/null"
      // Format strings used for system recon
      $sys_recon1 = "{\"ver\":\"%x\",\"mods\";["
      $sys_recon2 = "uptime: %lu mem_size: %lu mem_free: %lu"
      $sys_recon3 = "disk_size: %lu disk_free: %lu"
      $sys_recon4 = "hw: %02x:%02x:%02x:%02x:%02x:%02x"
      // Format string for filepath used to test access to device filesystem
      $testpath = "%s/214688dsf46"
      // Format string for implant configuration filepath
      $confpath = "%s/rootfs_cfg"
      // Default file download path
      $downpath = "/var/tmp/a.tmp"
   condition:
      (uint32(0) == 0x464c457f) and (8 of them)
}
