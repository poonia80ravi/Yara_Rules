rule win_unidentified_072_w0 {
    meta:
        author = "jeFF0Falltrades"
        ref = "https://blog.trendmicro.com/trendlabs-security-intelligence/analysis-abuse-of-custom-actions-in-windows-installer-msi-to-run-malicious-javascript-vbscript-and-powershell-scripts/"
        description = "This is a simple, albeit effective rule to detect most Metamorfo initial MSI payloads"
        source = "https://github.com/jeFF0Falltrades/IoCs/blob/master/Broadbased/metamorfo.md"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_072"
        malpedia_version = "20200211"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $str_1 = "replace(\"pussy\", idpp)" wide ascii nocase
        $str_2 = "GAIPV+idpp+\"\\\\\"+idpp" wide ascii nocase
        $str_3 = "StrReverse(\"TEG\")" wide ascii nocase
        $str_4 = "taller 12.2.1" wide ascii nocase
        $str_5 = "$bExisteArquivoLog" wide ascii nocase
        $str_6 = "function unzip(zipfile, unzipdir)" wide ascii nocase
        $str_7 = "DonaLoad(ArquivoDown" wide ascii nocase
        $str_8 = "putt_start" wide ascii nocase
        $str_9 = "FilesInZip= zipzipp" wide ascii nocase
        $str_10 = "@ u s e r p r o f i l e @\"+ppasta" wide ascii nocase
        $str_11 = "getFolder(unzipdir).Path" wide ascii nocase

    condition:
        2 of them
}
