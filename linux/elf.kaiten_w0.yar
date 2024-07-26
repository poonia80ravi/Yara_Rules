import "elf"

rule elf_kaiten_w0 {
    meta:
        author = "Akamai SIRT"
        description = "Kaiten/STD DDoS malware"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.kaiten"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $s0 = "shitteru koto dake"
        $s1 = "nandemo wa shiranai wa yo,"
    condition:
        elf.number_of_sections == 0 and
        elf.number_of_segments == 2 and
        $s0 and $s1
}
