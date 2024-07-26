rule win_boostwrite_w0 {
    meta:
        author = "Nick Carr (@itsreallynick)"
        reference = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boostwrite"
        malpedia_version = "20191012"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $weetPDB = /RSDS[\x00-\xFF]{20}[a-zA-Z]?:?\\[\\\s|*\s]?.{0,250}\\DWriteImpl[\\\s|*\s]?.{0,250}\.pdb\x00/ nocase

    condition:
        (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $weetPDB and filesize < 6MB
}
