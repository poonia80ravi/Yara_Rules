rule win_anchor_w1 {
    meta:
        author = "Jason Reaves"
        description = "For x64 Anchor"
        source = "https://labs.sentinelone.com/deep-dive-into-trickbot-executor-module-mexec-hidden-anchor-bot-nexus-operations/"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anchor"
        malpedia_version = "20200413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $xor_data = {80 ?4 0? ?? ?? 48 ?? c? 48}
        $hexlify = {81 c1 f0 00 00 00 23 d1 41 8? ?? c1 e1 02}
        $a1 = "/1001/" ascii wide
        $a2 = ":$GUID" ascii wide
        $a3 = ":$TASK" ascii wide
        $ua = "WinHTTP loader/1.0" ascii wide

    condition:
       3 of them
}
