rule elf_suterusu_w0 {
    meta:
        description = "Detects Linux HCRootkit, as reported by Avast"
        hash1 = "2daa5503b7f068ac471330869ccfb1ae617538fecaea69fd6c488d57929f8279"
        hash2 = "10c7e04d12647107e7abf29ae612c1d0e76a79447e03393fa8a44f8a164b723d"
        hash3 = "602c435834d796943b1e547316c18a9a64c68f032985e7a5a763339d82598915"
        author = "Lacework Labs"
        ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.suterusu"
        malpedia_version = "20211008"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a1 = "172.96.231."
        $a2 = "/tmp/.tmp_XXXXXX"
        $s1 = "/proc/net/tcp"
        $s2 = "/proc/.inl"
        $s3 = "rootkit"
    condition:
        uint32(0)==0x464c457f and 
        ((any of ($a*)) and (any of ($s*)))
}
