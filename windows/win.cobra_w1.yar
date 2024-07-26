import "pe"

rule win_cobra_w1 {
    meta:
        author = "ESET Research"
        source = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/#_footnote_2"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobra"
        malpedia_version = "20170512"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""

    condition:
        (pe.version_info["InternalName"] contains "SERVICE.EXE" or
        pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or
        pe.version_info["InternalName"] contains "MSXIML.DLL")
        and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
