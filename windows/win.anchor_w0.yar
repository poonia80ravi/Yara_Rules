rule win_anchor_w0 {
    meta:
        author = "Jason Reaves"
        description = "For x86 Anchor"
        source = "https://labs.sentinelone.com/deep-dive-into-trickbot-executor-module-mexec-hidden-anchor-bot-nexus-operations/"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anchor"
        malpedia_version = "20200413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a1 = "/1001/" ascii wide
        $a2 = ":$GUID" ascii wide
        $a3 = ":$TASK" ascii wide
        $ua = "WinHTTP loader/1.0" ascii wide
        $hexlify = {0f be ?? ?? b8 f0 00 00 00 0f 45 ?? 8b ?? c1 e1 02 23 d0}
        $sdecode = {8a 04 0a 0f be c0 83 e8 ?? 88 04 0a 42 83}
        $xor_data = {80 b4 05 ?? ?? ff ff ?? 40 3b c6}

    condition:
        3 of them
}
