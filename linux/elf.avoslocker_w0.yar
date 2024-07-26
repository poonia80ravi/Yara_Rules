rule elf_avoslocker_w0 {
	meta:
		description = "AvosLocker Ransomware"
		author = "VMware Threat Research"
		exemplar_hashes = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
		source = "https://blogs.vmware.com/security/2022/02/avoslocker-modern-linux-ransomware-threats.html"
        malpedia_rule_date = "20220322"
        malpedia_hash = ""
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.avoslocker"
		malpedia_version = "20220322"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
	strings:
		$s1 = "avoslinux" wide ascii nocase
		$s2 = "README_FOR_RESTORE" wide ascii nocase
		$s3 = "Killing ESXi VMs" wide ascii nocase
	condition:
		uint32(0) == 0x464C457F and filesize > 1MB and filesize < 3MB and
		all of ($s*)
}
