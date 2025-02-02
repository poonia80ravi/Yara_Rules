rule elf_kinsing_w0 {
    meta:
        description = "Rule to find Kinsing malware"
        author = "Tony Lambert, Red Canary"
        date = "2020-06-09"
        source = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_h2miner_kinsing.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.kinsing"
        malpedia_rule_date = "20200901"
        malpedia_version = "20200901"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "-iL $INPUT --rate $RATE -p$PORT -oL $OUTPUT"
        $s2 = "libpcap"
        $s3 = "main.backconnect"
        $s4 = "main.masscan"
        $s5 = "main.checkHealth"
        $s6 = "main.redisBrute"
        $s7 = "ActiveC2CUrl"
        $s8 = "main.RC4"
        $s9 = "main.runTask"
    condition:
        (uint32(0) == 0x464C457F) and filesize > 1MB and all of them 
}
