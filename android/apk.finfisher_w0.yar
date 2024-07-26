// Published under the GNU-GPLv2 license. It’s open to any user or organization,
//    as long as you use it under this license.

rule apk_finfisher_w0 {
    meta:
        description = "Detect Gamma/FinFisher FinSpy for Android #GovWare"
        date = "2020/01/07"
        author = "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)"
		reference = "https://github.com/devio/FinSpy-Tools"
		reference = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference = "https://www.ccc.de/de/updates/2019/finspy"
        hash = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/apk.finfisher"
        malpedia_version = "20200109"
        malpedia_sharing = "TLP:WHITE"
        malpedia_license = ""

    strings:
        $re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/
    condition:
        $re and (#re > 50)
}


