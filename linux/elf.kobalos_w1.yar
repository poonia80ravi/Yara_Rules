rule elf_kobalos_w1 {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.kobalos"
        malpedia_rule_date = "20210202"
        malpedia_hash = ""
        malpedia_version = "20210202"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

    condition:
        any of them
}
