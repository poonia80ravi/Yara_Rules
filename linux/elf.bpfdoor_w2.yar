rule elf_bpfdoor_w2 {
    meta:
        description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
        author = "Florian Roth"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-08"
        score = 85
        hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
        version = "1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bpfdoor"
        malpedia_rule_date = "20220509"
        malpedia_hash = ""
        malpedia_version = "20220509"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $s2 = "/sbin/mingetty /dev" ascii fullword
        $s3 = "pickup -l -t fifo -u" ascii fullword
    condition:
        uint16(0) == 0x457f and
        filesize < 200KB and 2 of them or all of them
}
