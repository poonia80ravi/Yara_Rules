rule win_redalpha_w1 {
    meta:
        desc = "RedAlpha 2017 Campaign, NetHelp Drop"
        author = "JAG-S, Insikt Group, RecordedFuture"
        TLP = "White"
        source = "https://www.recordedfuture.com/redalpha-cyber-campaigns/"
        md5_x86 = "42256b4753724f7feb411bc9912155fd"
        md5_x86 = "6d1d6987d0677f40e473befab121ab1b"
        md5_x64 = "8f0fe2620f8dadf93eee285834e35655"
        md5_x64 = "cd32ce54ed94dfbde7fb85930a16597d"
        md5_x64_striker = "6dd1be1e491d5bf9cd14686c185c3009"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redalpha"
        malpedia_version = "20180706"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $postreq1 = "POST /index.html HTTP/1.1" ascii wide
        $postreq2 = "Host: index.ackques.com" ascii wide
        $postreq3 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Chrome /53.0" ascii wide
        $postreq4 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*" ascii wide
        $postreq5 = "Accept-Language: en-US;q=0.5,en;q=0.3" ascii wide
        $postreq6 = "Accept-Encoding: gzip, deflate" ascii wide
        $postreq7 = "Content-Type: application/x-www-form-urlencoded" ascii wide
        $postreq8 = "Content-Length: %d" ascii wide
        $postreq9 = "Connection: keep-alive" ascii wide
        $postreq10 = "Upgrade-Insecure-Requests: 1" ascii wide
        $cnc1 = "index.ackques.com" ascii wide
        $cnc2 = "www.hktechy.com" ascii wide
        $cnc3 = "striker.internetdocss.com" ascii wide
        $service1 = "Windows Internet Help" ascii wide
        $service2 = "Client.dll" ascii wide
        $service3 = "ServiceMain" ascii wide
    condition:
    ( all of ($postreq*) or any of ($cnc*) or all of ($service*) )
}
