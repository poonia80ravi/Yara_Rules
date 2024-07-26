rule win_graphite_w0 {

    meta:
        date = "2022-08-05"
        description = "Detects Fancy Bear Graphite variant through internal strings"
        author = "Cluster25"
        tlp = "white"
        hash1 = "34aca02d3a4665f63fddb354551b5eff5a7e8877032ddda6db4f5c42452885ad"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphite"
        malpedia_rule_date = "20220926"
        malpedia_hash = ""
        malpedia_version = "20220926"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $ = "_LL_x64.dll" fullword ascii
        $ = "qqhqx!iwwU1ptzd1WngCv9BCmVtxgFTJBPR1bJ2Ze17e0N6W3VHZC2FQOOUhu4nQ2Wrj0qLEBowQ$$" ascii
        $ = "62272a08-fe9d-4825-bc65-203842ff92bc" fullword ascii
        $ = "%s %04d sp%1d.%1d %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and
        filesize < 100KB and
        all of them
}
