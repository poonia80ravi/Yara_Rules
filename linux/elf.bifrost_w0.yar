rule elf_bifrost_w0 {

    meta:
        author = "TeamT5"
        date = "2020-04-15"
        version = "1"
        description = "HUAPI UNIX BiFrost RAT"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bifrost"
        malpedia_rule_date = "20210331"
        malpedia_hash = ""
        malpedia_version = "20210331"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $hex1 = {25 ?? 00 00 00 85 C0 75 37 8B 45 F0 89 C1 03 4D 08 8B 45 F0 03 45 08 0F B6 10 8B 45 F8 01 C2 B8 FF FF FF FF 21 D0 88 01 8B 45 F0 89 C2 03 55 08 8B 45 F0 03 45 08 0F B6 00 32 45 FD 88 02}
        $hex2 = {8B 45 F0 03 45 08 0F B6 00 30 45 FD 8B 45 F0 89 C1 03 4D 08 8B 45 F8 89 C2 02 55 FD B8 FF FF FF FF 21 D0 88 01}
        
    condition:
        all of them
}
