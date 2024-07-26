import "pe"

rule win_industroyer_w0 {
    meta:
        description = "CRASHOVERRIDE v1 Suspicious Export"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    condition:
        pe.exports("Crash") & pe.characteristics
}

